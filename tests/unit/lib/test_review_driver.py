# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The batch driver (lib/review_driver, tmap review <run_pair> --agent): one launch per unit,
success read from overlay_history only, retries, the first unit as a probe, the tool-set probe,
the deadline, and the blind launch of an audit unit.

Zero real data: the callee-group World of test_callee_groups; the agent is simulated in-process
(an injected runner), except where a real process is the point (the deadline, the command line)."""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_callee_groups import _fresh, _world  # noqa: F401 — autouse fixture
from treasure_map.lib import overlay
from treasure_map.lib import review_driver as rd
from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.query import review_units as ru

PRESET = rd.Preset("test", ("agent", "{unit_id}", "{prompt}"), blind_argv=("--deny", "list"))


def _units(w: Any) -> dict[str, ru.Unit]:
    return _units_at(w, 50)


def _units_at(w: Any, k: int) -> dict[str, ru.Unit]:
    r = ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        k=k,
        pair_staleness={"source_stale": False, "source_stale_reason": None},
        server_commit=None,
    )
    return {u.unit_id: u for u in r.units}


def _group_ref(u: ru.Unit | None, m: ru.Member) -> str | None:
    """The group_ref a member is judged with: its group unit's, or the one a reduce names."""
    if u is None:
        return None
    if u.group is not None:
        return str(u.group.get("ref"))
    named = [r.split(":", 1)[1] for r in m.reasons if r.startswith("group_ref:")]
    return named[0] if named else None


def _agent(w: Any, judge: str = "all", calls: list[list[str]] | None = None) -> Any:
    """A simulated agent: judges the members of the unit its prompt names — all, the first only,
    or none — through annotate_diff with the unit's id, as a launched agent would."""

    def run(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        if calls is not None:
            calls.append(list(argv))
        uid = re.search(r'unit="([0-9a-f]{16})"', argv[-1])
        assert uid is not None
        u = _units(w).get(uid.group(1))
        members = [] if u is None or judge == "none" else list(u.members)
        if judge == "first":
            members = members[:1]
        for m in members:
            if m.kind != "entry":
                continue
            overlay.annotate_diff(
                w.atlas,
                anchor_ref=m.anchor_ref,
                verdict="changed_real",
                rationale="r",
                diff_id=m.stream,
                group_ref=_group_ref(u, m),
                ctx=overlay.WriteContext(channel="mcp", unit_id=uid.group(1), session="agent"),
                shadow=u is not None and u.kind == ru.AUDIT,
            )
        return rd.Launch(0, 0.01, False)

    return run


def _drive(w: Any, tmp: Path, runner: Any, **kw: Any) -> rd.DriveResult:
    return rd.drive(
        w.path,
        "runA",
        "runB",
        PRESET,
        workdir=tmp,
        k=50,
        runner=runner,
        echo=lambda s: None,
        **kw,
    )


def test_the_driver_reviews_every_unit_and_reads_success_from_the_history(tmp_path: Path) -> None:
    """★ One launch per unit, each judging every member under the unit's id: every unit succeeds,
    the loop ends with no unit left, and each launch is logged beside the tool-call log.

    MUTATION (verified RED): count a unit done on the agent's exit code -> the 'none' agent below
    passes -> RED (the next test)."""
    w = _world(tmp_path)
    result = _drive(w, tmp_path, _agent(w), max_units=50)
    assert result.failed == [] and result.stopped == "no unit left"
    assert result.units_done == result.units_tried > 0
    log = tcl.read_lines(tcl.log_path_for(w.path).with_name(rd.DRIVER_LOG))
    assert log is not None and all(ln.get("success") for ln in log)


def test_a_launch_that_writes_nothing_fails_and_the_first_stops_the_loop(tmp_path: Path) -> None:
    """★ Exit 0 and no write is a failure, retried, then the loop stops on the first unit with
    the reason; nothing is counted done.

    MUTATION (verified RED): believe the exit code -> units_done > 0 -> RED; retry nothing -> one
    launch -> RED."""
    w = _world(tmp_path)
    calls: list[list[str]] = []
    result = _drive(w, tmp_path, _agent(w, "none", calls), retries=2)
    assert result.units_done == 0 and len(calls) == 3
    assert result.stopped is not None and "wrote nothing" in result.stopped


def test_a_unit_judged_in_part_is_not_done(tmp_path: Path) -> None:
    """★ A launch that judges some members only does not complete the unit: it is handed out again,
    and once a launch disposes no new member (this agent judges the first member again) it is
    retried, then left as failed (named), and the loop goes on to the next.

    MUTATION (verified RED): count a unit done on any write naming it -> RED."""
    w = _world(tmp_path)
    group = next(u for u in _units(w).values() if len(u.members) > 1)
    calls: list[list[str]] = []

    def partial(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        if group.unit_id in argv[-1]:
            return _agent(w, "first", calls)(argv, cwd=cwd, timeout=timeout)
        return _agent(w, "all", calls)(argv, cwd=cwd, timeout=timeout)

    result = _drive(w, tmp_path, partial, retries=1, max_units=50)
    assert [f["unit_id"] for f in result.failed] == [group.unit_id]
    assert result.failed[0]["written"] == 1
    assert result.units_done == result.units_tried - 1


def _one_listed_member_agent(w: Any, k: int, launches: dict[str, int]) -> Any:
    """A simulated agent that goes through the MCP server as a launched one does: a fresh server
    per launch, start_diff_review(unit=…) for the unit its prompt names, then ONE annotate_diff
    with that unit_id, on the first member the page lists that is not judged yet — so the write
    records the read basis the server gives it (unit_delivered)."""
    from tests.unit.test_tool_surface import _call
    from treasure_map import mcp_app

    def run(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        uid = re.search(r'unit="([0-9a-f]{16})"', argv[-1])
        assert uid is not None
        launches[uid.group(1)] = launches.get(uid.group(1), 0) + 1
        server = mcp_app.build_server(w.path)
        page = _call(
            server, "start_diff_review", {"run_pair": "runA::runB", "unit": uid.group(1), "k": k}
        )
        todo = [m for m in page["members"] if m.get("review_state") in (None, "none")]
        assert todo, page
        out = _call(
            server,
            "annotate_diff",
            {
                "anchor_ref": todo[0]["anchor_ref"],
                "verdict": "changed_real",
                "rationale": "r",
                "diff_id": page["unit"]["stream"],
                "unit_id": uid.group(1),
            },
        )
        assert out.get("written") is True, out
        return rd.Launch(0, 0.01, False)

    return run


def test_a_unit_judged_one_member_per_launch_is_handed_out_until_disposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A launch that disposes one new member hands the same unit out again without spending a
    retry: with retries=0, a six-member batch whose agent judges one listed member per launch
    (through the server, so each write reads unit_delivered) is launched six times and completes;
    nothing fails, and no member is judged twice.

    MUTATION (verified RED, 1 failed): count a launch that disposes a new member but not all
    against the retries (the old one-launch-per-unit loop) -> the batch fails after one launch ->
    RED."""
    from tests.unit.lib.test_review_units import _wide_world

    w = _wide_world(tmp_path, monkeypatch, 6)
    batch = next(u for u in _units_at(w, 0).values() if len(u.members) > 1)
    assert len(batch.members) == 6 and all(m.kind == "entry" for m in batch.members)
    launches: dict[str, int] = {}
    result = rd.drive(
        w.path,
        "runA",
        "runB",
        PRESET,
        workdir=tmp_path,
        k=0,
        retries=0,
        runner=_one_listed_member_agent(w, 0, launches),
        echo=lambda s: None,
    )
    assert result.failed == [] and result.stopped == "no unit left", result
    assert launches[batch.unit_id] == len(batch.members)
    assert result.units_done == result.units_tried == len(launches)
    rows = w.atlas.execute(
        "SELECT anchor_ref, COUNT(*), MAX(read_basis) FROM overlay_history WHERE unit_id = ? "
        "GROUP BY anchor_ref",
        (batch.unit_id,),
    ).fetchall()
    assert {r[0] for r in rows} == {m.anchor_ref for m in batch.members}
    assert all(r[1] == 1 and json.loads(r[2]).get("basis") == "unit_delivered" for r in rows)


def test_a_unit_handed_out_again_is_not_launched_past_max_minutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ max_minutes holds between the launches of one unit too: a six-member batch whose agent
    disposes one member per launch, each launch taking two minutes of a one-minute drive, is
    launched once — the drive stops with the reason and names the unit failed with why — not six
    times past its limit.

    MUTATION (verified RED, 1 failed): check the deadline only before a new unit (as before) ->
    six launches -> RED."""
    from tests.unit.lib.test_review_units import _wide_world

    w = _wide_world(tmp_path, monkeypatch, 6)
    batch = next(u for u in _units_at(w, 0).values() if len(u.members) > 1)
    assert len(batch.members) == 6
    clock = [0.0]

    class _Time:
        def __getattr__(self, name: str) -> Any:
            return getattr(time, name)

        def monotonic(self) -> float:
            return clock[0]

    monkeypatch.setattr(rd, "time", _Time())
    launches: dict[str, int] = {}
    agent = _one_listed_member_agent(w, 0, launches)

    def slow(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        clock[0] += 120.0
        return agent(argv, cwd=cwd, timeout=timeout)

    result = rd.drive(
        w.path,
        "runA",
        "runB",
        PRESET,
        workdir=tmp_path,
        k=0,
        max_minutes=1,
        runner=slow,
        echo=lambda s: None,
    )
    assert launches == {batch.unit_id: 1}, launches
    assert result.stopped == "max_minutes 1 reached", result
    assert [(f["unit_id"], f.get("why")) for f in result.failed] == [
        (batch.unit_id, "max_minutes 1 reached")
    ]


def test_a_unit_written_but_read_as_needs_recheck_is_not_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Success is the unit disposed, not written: a launch that writes every member naming the
    unit, each judged before anything was read (so the subject reads needs_recheck), leaves the
    unit owed — the launch disposes nothing new, so it is retried and then left as failed.

    MUTATION (verified RED, 1 failed): count a unit done when every member is written -> the
    unit succeeds -> RED."""
    from tests.unit.lib.test_review_units import _wide_world

    w = _wide_world(tmp_path, monkeypatch, 3)
    batch = next(u for u in _units_at(w, 0).values() if len(u.members) > 1)
    calls: list[int] = []

    def unread(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        calls.append(1)
        for m in batch.members:
            overlay.annotate_diff(
                w.atlas,
                anchor_ref=m.anchor_ref,
                verdict="changed_real",
                rationale="r",
                diff_id=m.stream,
                ctx=overlay.WriteContext(
                    channel="mcp",
                    unit_id=batch.unit_id,
                    session="agent",
                    read_basis={"basis": "none", "unread_before_verdict": True},
                ),
            )
        return rd.Launch(0, 0.01, False)

    result = rd.drive(
        w.path,
        "runA",
        "runB",
        PRESET,
        workdir=tmp_path,
        k=0,
        retries=1,
        runner=unread,
        echo=lambda s: None,
    )
    assert result.units_done == 0 and len(calls) == 2
    assert [f["unit_id"] for f in result.failed] == [batch.unit_id]
    assert result.failed[0]["written"] == len(batch.members) and result.failed[0]["disposed"] == 0


def test_the_unit_prompt_says_judge_the_listed_members_and_read_a_cut_page_first() -> None:
    """★ The unit prompt names the members the page lists, says the unit comes back until all are
    judged, and that a page with material_cut true is read to its end (read_more / read_one) before
    judging.

    MUTATION (verified RED, 1 failed): the old prompt text ('Judge EVERY member with …', 'Then
    stop.') -> RED."""
    text = rd.unit_prompt("a::b", ru.Unit("0" * 16, ru.S_BATCH, True, (), "s", 0, 0), 4)
    assert "Judge EVERY member listed in members" in text
    assert "the unit comes back until all its members are judged" in text
    assert "material_cut is true, first read the rest with the read_more / read_one" in text


def test_an_audit_unit_is_launched_blind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ An audit unit's launch carries the preset's blind arguments (list_overlays denied) and
    its prompt says it is an audit. (Blind auditing is sealed by default; this test turns it on so
    an audit unit is produced to launch.)

    MUTATION (verified RED): render every launch alike -> RED."""
    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    w = _world(tmp_path)
    _drive(w, tmp_path, _agent(w), max_units=50)  # everything judged first
    anchor = next(m.anchor_ref for u in _units(w).values() for m in u.members if m.kind == "entry")
    overlay.annotate_diff(
        w.atlas,
        anchor_ref=anchor,
        verdict="change_inconclusive",
        rationale="r",
        diff_id="runA::runB::libx",
        ctx=overlay.WriteContext(channel="mcp", session="writer"),
    )
    calls: list[list[str]] = []
    _drive(w, tmp_path, _agent(w, "all", calls), max_units=50)
    blind = [c for c in calls if "AUDIT" in c[-1]]
    assert blind and all("--deny" in c for c in blind)
    assert all("--deny" not in c for c in calls if "AUDIT" not in c[-1])


@pytest.mark.parametrize(
    ("reach", "write_file", "ok"),
    [(True, False, True), (False, False, False), (True, True, False)],
    ids=["ok", "no_tmap", "builtin_open"],
)
def test_the_probe_needs_tmap_reached_and_builtin_tools_off(
    tmp_path: Path, reach: bool, write_file: bool, ok: bool
) -> None:
    """★ The probe passes only when the agent reached a tmap tool (in the tool-call log) and could
    not create the marker file with a built-in tool.

    MUTATION (verified RED): skip the marker check -> builtin_open passes -> RED; skip the log
    check -> no_tmap passes -> RED."""
    atlas = tmp_path / "atlas.db"

    def agent(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        if reach:
            log = tcl.ToolCallLog(tcl.log_path_for(atlas))
            log.record("list_runs", {}, {"runs": []})
        if write_file:
            (cwd / "probe_marker.txt").write_text("probe")
        return rd.Launch(0, 0.0, False)

    got = rd.probe(PRESET, atlas_path=atlas, workdir=tmp_path, timeout=5, runner=agent)
    assert got.ok is ok
    assert (got.tmap_reached, got.builtin_blocked) == (reach, not write_file)


def test_a_preset_with_blind_argv_is_probed_blind_too(tmp_path: Path) -> None:
    """★ A-4 / acceptance 12: a preset carrying blind_argv is probed twice — once plain, once with
    the blind argv — so the blind launch is proven to still reach a tmap tool (the blind argv did
    not swallow the prompt). A preset with no blind_argv is probed once.

    MUTATION (verified RED): probe only once -> the blind launch never runs -> RED."""
    atlas = tmp_path / "atlas.db"
    launches: list[list[str]] = []

    def agent(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        launches.append(list(argv))
        tcl.ToolCallLog(tcl.log_path_for(atlas)).record("list_runs", {}, {"runs": []})
        return rd.Launch(0, 0.0, False)

    got = rd.probe(PRESET, atlas_path=atlas, workdir=tmp_path, timeout=5, runner=agent)
    assert got.ok is True
    assert len(launches) == 2
    assert sum("--deny" in argv for argv in launches) == 1  # exactly one blind launch

    launches.clear()
    plain = rd.Preset("plain", ("agent", "{prompt}"))  # no blind_argv
    rd.probe(plain, atlas_path=atlas, workdir=tmp_path, timeout=5, runner=agent)
    assert len(launches) == 1


def test_a_launch_past_its_deadline_is_killed_whole(tmp_path: Path) -> None:
    """A launch past its deadline is killed with its process group: it reads timed out, and a
    child it started does not outlive it.

    MUTATION (verified RED): kill only the launched process -> the child survives -> RED."""
    marker = tmp_path / "child_alive"
    script = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', \"import time; time.sleep(3); "
        f"open({str(marker)!r}, 'w').write('x')\"])\n"
        "time.sleep(60)\n"
    )
    t0 = time.monotonic()
    got = rd.run_agent([sys.executable, "-c", script], cwd=tmp_path, timeout=1)
    assert got.timed_out and got.exit is None and time.monotonic() - t0 < 10
    time.sleep(4)
    assert not marker.exists()


def test_the_claude_preset_switches_builtin_tools_off_and_loads_only_tmap() -> None:
    """The claude-code preset: tmap's MCP server alone (--strict-mcp-config), every built-in tool
    off (--tools ""), tmap's tools pre-allowed, no prompt, no user settings; the audit launch
    denies list_overlays.

    MUTATION (verified RED): drop --tools "" from the preset -> RED."""
    argv = rd.render(
        rd.PRESETS["claude-code"],
        {
            "prompt": "P",
            "mcp_config": "/m.json",
            "workdir": "/w",
            "atlas": "/a",
            "unit_id": "u",
            "run_pair": "r",
            "tmap": "tmap",
        },
        blind=True,
    )
    assert "--tools" in argv and argv[argv.index("--tools") + 1] == ""
    assert "--strict-mcp-config" in argv and argv[argv.index("--mcp-config") + 1] == "/m.json"
    assert argv[argv.index("--allowedTools") + 1] == "mcp__treasure-map__*"
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"
    # One token with '=' (A-4): the two-token form is parsed greedily and swallows the prompt.
    assert "--disallowedTools=mcp__treasure-map__list_overlays" in argv
    assert "--disallowedTools" not in argv
    assert argv[-1] == "P"
    assert not rd.PRESETS["claude-code"].experimental and rd.PRESETS["codex"].experimental


def test_the_command_line_routes_a_run_pair_and_refuses_on_a_failed_probe(
    tmp_path: Path,
) -> None:
    """tmap review <run_pair> --agent <template> is the driver; an agent that reaches nothing fails
    the probe and no unit is handed out.

    MUTATION (verified RED): hand units out after a failed probe -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli.review_cli import review

    w = _world(tmp_path)
    template = f"{sys.executable} -c pass {{prompt}}"
    res = CliRunner().invoke(
        review, ["runA::runB", "--agent", template, "--atlas", str(w.path), "--timeout", "30"]
    )
    assert res.exit_code != 0
    assert "tmap reached False" in res.output and "probe failed" in res.output
    assert w.atlas.execute("SELECT COUNT(*) FROM overlay").fetchone()[0] == 0


_VALUES = {
    "prompt": "P",
    "mcp_config": "/m.json",
    "workdir": "/w",
    "atlas": "/a",
    "unit_id": "u",
    "run_pair": "r",
    "tmap": "tmap",
}


def test_the_handoff_launch_carries_the_findings_schema_and_no_unit_launch_does() -> None:
    """★ The claude-code hand-off launch carries --json-schema with HANDOFF_SCHEMA — the value, read
    back as JSON, is the module's constant (fixed keys: a findings list naming each anchor_ref) —
    before the prompt, which stays the last argument. A unit's launch (plain or blind) carries none.

    MUTATION (verified RED, ``1 failed``): fill placeholders in the hand-off argv too (its braces
    read as placeholders) -> KeyError, caught -> RED; never add the hand-off argv -> RED."""
    preset = rd.PRESETS["claude-code"]
    why = ""
    try:
        argv: list[str] | None = rd.render(preset, _VALUES, handoff=True)
    except (KeyError, IndexError, ValueError) as exc:  # a brace read as a placeholder
        argv, why = None, repr(exc)
    assert argv is not None, why
    assert argv.count("--json-schema") == 1, argv
    assert json.loads(argv[argv.index("--json-schema") + 1]) == rd.HANDOFF_SCHEMA
    assert argv[-1] == "P"
    items = rd.HANDOFF_SCHEMA["properties"]["findings"]["items"]
    assert set(items["required"]) == {"anchor_ref", *rd.HANDOFF_FIELDS}
    assert items["additionalProperties"] is False
    for blind in (False, True):
        assert "--json-schema" not in rd.render(preset, _VALUES, blind=blind)


def test_a_units_launch_from_the_drive_carries_no_handoff_argv(tmp_path: Path) -> None:
    """★ The drive's per-unit launches never carry the hand-off argv (the findings schema is for
    the final hand-off launch only; a unit's agent ends with a judgement, not that JSON).

    MUTATION (verified RED, ``1 failed``): render the drive's launches with handoff=True -> RED."""
    w = _world(tmp_path)
    preset = rd.Preset(
        "test", PRESET.argv, blind_argv=PRESET.blind_argv, handoff_argv=("--schema", "S")
    )
    calls: list[list[str]] = []
    rd.drive(
        w.path,
        "runA",
        "runB",
        preset,
        workdir=tmp_path,
        k=50,
        max_units=3,
        runner=_agent(w, "all", calls),
        echo=lambda s: None,
    )
    assert calls and all("--schema" not in c for c in calls), calls


def test_the_probe_tries_the_handoff_argv_when_the_handoff_will_run(tmp_path: Path) -> None:
    """★ With handoff=True the probe launches once more with the preset's hand-off argv (the
    findings schema), so an agent CLI that refuses it fails here, not after the whole review — and
    the reason names the option. Without handoff, no such launch.

    MUTATION (verified RED, ``1 failed``): never add the hand-off launch -> RED; drop the exit
    check -> the reason does not name the option -> RED."""
    atlas = tmp_path / "atlas.db"
    preset = rd.Preset(
        "test", PRESET.argv, blind_argv=PRESET.blind_argv, handoff_argv=("--schema", "{S}")
    )
    launches: list[list[str]] = []

    def agent(old_cli: bool) -> Any:
        def run(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
            launches.append(list(argv))
            if old_cli and "--schema" in argv:
                return rd.Launch(2, 0.0, False, "error: unknown option '--schema'")
            tcl.ToolCallLog(tcl.log_path_for(atlas)).record("list_runs", {}, {"runs": []})
            return rd.Launch(0, 0.0, False)

        return run

    got = rd.probe(preset, atlas_path=atlas, workdir=tmp_path, timeout=5, runner=agent(False))
    assert got.ok is True and len(launches) == 2
    assert all("--schema" not in a for a in launches)
    launches.clear()
    got = rd.probe(
        preset, atlas_path=atlas, workdir=tmp_path, timeout=5, runner=agent(False), handoff=True
    )
    assert got.ok is True and len(launches) == 3
    (with_schema,) = [a for a in launches if "--schema" in a]
    assert with_schema[-3:-1] == ["--schema", "{S}"] and "--deny" not in with_schema
    launches.clear()
    got = rd.probe(
        preset, atlas_path=atlas, workdir=tmp_path, timeout=5, runner=agent(True), handoff=True
    )
    assert got.ok is False
    assert "the launch with --schema exited 2" in got.why, got.why
