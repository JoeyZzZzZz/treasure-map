# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The batch driver: tmap hands a run pair's review out one work unit at a time, each to a fresh
run of the user's own agent command line — tmap runs the loop, the agent judges one unit and exits.

tmap calls no model API. Each launch is non-interactive, loads the tmap MCP server (a config file
written here) and, for a preset, is limited to tmap's tools: an agent CLI's "allowed tools" flag
usually means "no confirmation needed", not "nothing else", so a preset also switches every
built-in tool off. Before any unit, a probe checks it: the agent must reach a tmap tool, and an
attempt to write a file with a built-in tool must fail. An experimental template is run only once
that probe passes on this machine.

A unit succeeds only when, after its launch, overlay_history holds a judgement naming the unit for
EVERY one of its members — neither the agent's exit code nor its output is believed. A launch is
killed at its deadline; a failed unit is retried, then left (named in the log) and the loop moves
on. The first unit doubles as a probe of the whole chain: when it writes nothing, the loop stops
and says why. An audit unit's launch is also denied the tool that returns the judgements
(list_overlays), so it reads blind.

Each launch is logged — unit, attempt, exit status, seconds, members written — in
``<atlas dir>/logs/review_driver.jsonl`` (outside the atlas, like the tool-call log).
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.query import review_units as ru

DEFAULT_TIMEOUT = 15 * 60
DEFAULT_RETRIES = 2
SERVER_NAME = "treasure-map"
DRIVER_LOG = "review_driver.jsonl"
# Environment markers an agent's shell sets: not passed to the launched agent, which is a fresh one.
_PARENT_AGENT_ENV = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")


@dataclass(frozen=True)
class Preset:
    """An agent command line: argv with ``{prompt}`` / ``{mcp_config}`` / ``{workdir}`` /
    ``{atlas}`` / ``{unit_id}`` / ``{run_pair}`` placeholders, and the argv added for a blind
    (audit) launch. ``experimental``: not verified here — it runs only after its probe passes."""

    name: str
    argv: tuple[str, ...]
    blind_argv: tuple[str, ...] = ()
    experimental: bool = False
    note: str = ""


PRESETS: dict[str, Preset] = {
    "claude-code": Preset(
        "claude-code",
        (
            "claude",
            "-p",
            "--mcp-config",
            "{mcp_config}",
            "--strict-mcp-config",
            "--tools",
            "",
            "--allowedTools",
            f"mcp__{SERVER_NAME}__*",
            "--permission-mode",
            "dontAsk",
            "--setting-sources",
            "",
            "--output-format",
            "json",
            "--no-session-persistence",
            "{prompt}",
        ),
        blind_argv=("--disallowedTools", f"mcp__{SERVER_NAME}__list_overlays"),
        note=(
            '--allowedTools only skips confirmation; --tools "" switches every built-in tool '
            'off and --setting-sources "" loads no user or project settings'
        ),
    ),
    "codex": Preset(
        "codex",
        (
            "codex",
            "exec",
            "--skip-git-repo-check",
            "-c",
            f'mcp_servers.{SERVER_NAME}.command="{{tmap}}"',
            "-c",
            f'mcp_servers.{SERVER_NAME}.args=["mcp","--atlas","{{atlas}}"]',
            "{prompt}",
        ),
        experimental=True,
        note="experimental: calls have been reported cancelled or hanging; probe first",
    ),
    "cursor": Preset(
        "cursor",
        ("cursor-agent", "-p", "--approve-mcps", "--trust", "{prompt}"),
        experimental=True,
        note=(
            "experimental: needs the tmap MCP server registered and an Mcp(treasure-map:*) "
            "allow-list in its own configuration; probe first"
        ),
    ),
}


def preset_or_template(agent: str) -> Preset:
    """A preset by name, or a command template (it must hold ``{prompt}``), taken as
    experimental."""
    if agent in PRESETS:
        return PRESETS[agent]
    argv = tuple(shlex.split(agent))
    if not argv or not any("{prompt}" in a for a in argv):
        raise ValueError(
            f"--agent takes a preset ({', '.join(PRESETS)}) or a command template holding "
            "{prompt}"
        )
    return Preset("template", argv, experimental=True, note="a command template: probe first")


def tmap_command() -> list[str]:
    """How the launched agent starts tmap's MCP server: the installed executable, else this
    interpreter running the package."""
    from treasure_map.lib.setup.clients import tmap_executable

    exe = tmap_executable()
    return [str(exe)] if exe is not None else [sys.executable, "-m", "treasure_map.cli.main"]


def write_mcp_config(path: Path, atlas: Path) -> Path:
    cmd = tmap_command()
    config = {
        "mcpServers": {
            SERVER_NAME: {"command": cmd[0], "args": [*cmd[1:], "mcp", "--atlas", str(atlas)]}
        }
    }
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return path


def render(preset: Preset, values: dict[str, str], *, blind: bool = False) -> list[str]:
    """The argv of one launch: the preset's placeholders filled; a blind launch adds its argv
    before the last argument (the prompt)."""
    argv = [a.format(**values) if "{" in a else a for a in preset.argv]
    if blind and preset.blind_argv:
        argv = [*argv[:-1], *preset.blind_argv, argv[-1]]
    return argv


def unit_prompt(run_pair: str, u: ru.Unit, k: int) -> str:
    kk = f", k={k}" if k != ru.DEFAULT_K else ""
    text = (
        f"You are reviewing ONE work unit of the firmware version diff {run_pair} with the tmap "
        "tools. tmap draws no conclusion: the judgment is yours, and it records nothing for you. "
        f'1. Call start_diff_review(run_pair="{run_pair}", unit="{u.unit_id}"{kk}) and read its '
        "material; when it says material_cut, read the rest with the calls it names. "
        "2. Judge EVERY member with annotate_diff (or annotate_diff_batch), passing "
        f'unit_id="{u.unit_id}": changed_real (with evidence and change_kind when you can), '
        "no_real_change (checked + why_unchanged), or change_inconclusive (what is missing). "
        "3. Then stop. Do not judge anything outside this unit."
    )
    if u.kind == ru.AUDIT:
        text += (
            " This is an AUDIT: read the subject afresh and judge it yourself; do not look for an "
            "earlier judgment (list_overlays is not available to you)."
        )
    if u.group is not None:
        text += f' Pass group_ref="{u.group.get("ref")}" with each member.'
    if u.kind == ru.REDUCE:
        text += (
            " This is the REDUCE: each member is owed a judgment leaning on its callee group — "
            "pass the group_ref its reasons name (group_ref:<ref>) with it."
        )
    return text


@dataclass
class Launch:
    exit: int | None
    seconds: float
    timed_out: bool
    output: str = ""


def run_agent(argv: Sequence[str], *, cwd: Path, timeout: float) -> Launch:
    """Run one agent launch in its own process group, killed whole at ``timeout``."""
    env = {k: v for k, v in os.environ.items() if k not in _PARENT_AGENT_ENV}
    t0 = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 — the user's own agent command line
        list(argv),
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
        return Launch(proc.returncode, time.monotonic() - t0, False, out[-4000:])
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.communicate()
        return Launch(None, time.monotonic() - t0, True)


def history_mark(atlas: sqlite3.Connection) -> int:
    row = atlas.execute("SELECT COALESCE(MAX(id), 0) FROM overlay_history").fetchone()
    return int(row[0])


def members_written(atlas: sqlite3.Connection, u: ru.Unit, after: int) -> set[str]:
    """The unit's members that overlay_history holds a judgement on, naming the unit, written after
    history row ``after``."""
    rows = atlas.execute(
        "SELECT DISTINCT anchor_ref FROM overlay_history WHERE unit_id = ? AND id > ? "
        "AND event IN ('insert', 'update', 'shadow')",
        (u.unit_id, after),
    ).fetchall()
    got = {r[0] for r in rows}
    return {m.anchor_ref for m in u.members} & got


@dataclass
class ProbeResult:
    ok: bool
    tmap_reached: bool
    builtin_blocked: bool
    why: str
    launch: Launch | None = None


def probe(
    preset: Preset,
    *,
    atlas_path: Path,
    workdir: Path,
    timeout: float,
    runner: Callable[..., Launch] = run_agent,
) -> ProbeResult:
    """One launch that must reach a tmap tool (list_runs, seen in the tool-call log) and must fail
    to create a file with a built-in tool (the marker file must not exist after it)."""
    marker = workdir / "probe_marker.txt"
    marker.unlink(missing_ok=True)
    started = time.time()
    prompt = (
        "This is a check of your tool set, nothing else. Step 1: call the tmap tool list_runs. "
        f"Step 2: if you have any tool that writes files or runs commands, use it to create the "
        f"file {marker} containing the word probe; if you have none, say so. Then stop."
    )
    values = _values(preset, atlas_path, workdir, prompt, "probe", "probe")
    launch = runner(render(preset, values), cwd=workdir, timeout=timeout)
    lines = tcl.read_lines(tcl.log_path_for(atlas_path)) or iter(())
    reached = any(
        ln.get("tool") == "list_runs" and float(ln.get("ts") or 0) >= started for ln in lines
    )
    blocked = not marker.exists()
    why = []
    if not reached:
        why.append("the agent never reached a tmap tool (is the MCP server loaded and allowed?)")
    if not blocked:
        why.append("the agent created a file with a built-in tool: built-in tools are not off")
    if launch.timed_out:
        why.append("the probe launch hit its deadline")
    return ProbeResult(reached and blocked, reached, blocked, "; ".join(why) or "ok", launch)


def _values(
    preset: Preset, atlas_path: Path, workdir: Path, prompt: str, unit_id: str, run_pair: str
) -> dict[str, str]:
    cfg = write_mcp_config(workdir / "mcp.json", atlas_path)
    return {
        "prompt": prompt,
        "mcp_config": str(cfg),
        "workdir": str(workdir),
        "atlas": str(atlas_path),
        "unit_id": unit_id,
        "run_pair": run_pair,
        "tmap": tmap_command()[0],
    }


@dataclass
class DriveResult:
    units_tried: int = 0
    units_done: int = 0
    failed: list[dict[str, Any]] = field(default_factory=list)
    stopped: str | None = None
    statement: str | None = None


def _log(path: Path, line: dict[str, Any]) -> None:
    tcl.append(path, {"ts": time.time(), **line})


def drive(
    atlas_path: Path,
    run_a: str,
    run_b: str,
    preset: Preset,
    *,
    workdir: Path,
    k: int = ru.DEFAULT_K,
    worker: int | None = None,
    workers: int | None = None,
    max_units: int | None = None,
    max_minutes: float | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    pair_staleness: dict[str, Any] | None = None,
    runner: Callable[..., Launch] = run_agent,
    echo: Callable[[str], None] = print,
) -> DriveResult:
    """Hand the pair's units out, one launch each, until none is left (or a limit is reached);
    see the module docstring."""
    from treasure_map.lib.atlas.connection import open_atlas

    run_pair = f"{run_a}::{run_b}"
    log_path = tcl.log_path_for(atlas_path).with_name(DRIVER_LOG)
    out = DriveResult()
    skip: set[str] = set()
    done_ids: set[str] = set()
    deadline = time.monotonic() + max_minutes * 60 if max_minutes else None
    staleness = pair_staleness or {"source_stale": False, "source_stale_reason": None}
    while True:
        if max_units is not None and out.units_tried >= max_units:
            out.stopped = f"max_units {max_units} reached"
            break
        if deadline is not None and time.monotonic() > deadline:
            out.stopped = f"max_minutes {max_minutes} reached"
            break
        atlas = open_atlas(atlas_path)
        try:
            review = ru.review_pair(
                atlas, run_a, run_b, k=k, pair_staleness=staleness, server_commit=None
            )
            nxt = next(
                (
                    u
                    for u in review.units
                    if u.unit_id not in skip
                    and ru.in_shard(u.unit_id, worker, workers)
                    and not ru.unit_disposed(u, review.progress.states)
                ),
                None,
            )
            out.statement = review.report["coverage_statement"]
            if nxt is None:
                out.stopped = "no unit left"
                break
            mark = history_mark(atlas)
        finally:
            atlas.close()
        if nxt.unit_id in done_ids:
            # Every member was written, yet the unit is still owed (a reduce member written
            # without its group_ref, say): counted failed once, never handed out again here.
            out.units_done -= 1
            out.failed.append(
                {
                    "unit_id": nxt.unit_id,
                    "kind": nxt.kind,
                    "written": len(nxt.members),
                    "members": len(nxt.members),
                    "why": "written but still owed",
                }
            )
            skip.add(nxt.unit_id)
            continue
        out.units_tried += 1
        prompt = unit_prompt(run_pair, nxt, k)
        values = _values(preset, atlas_path, workdir, prompt, nxt.unit_id, run_pair)
        argv = render(preset, values, blind=nxt.kind == ru.AUDIT)
        done = False
        written: set[str] = set()
        for attempt in range(1, retries + 2):
            launch = runner(argv, cwd=workdir, timeout=timeout)
            atlas = open_atlas(atlas_path)
            try:
                written = members_written(atlas, nxt, mark)
            finally:
                atlas.close()
            done = len(written) == len(nxt.members)
            _log(
                log_path,
                {
                    "run_pair": run_pair,
                    "unit_id": nxt.unit_id,
                    "kind": nxt.kind,
                    "attempt": attempt,
                    "exit": launch.exit,
                    "timed_out": launch.timed_out,
                    "seconds": round(launch.seconds, 1),
                    "members_written": len(written),
                    "members": len(nxt.members),
                    "success": done,
                },
            )
            echo(
                f"{nxt.unit_id} {nxt.kind} attempt {attempt}: "
                f"{len(written)}/{len(nxt.members)} written"
                + (" (deadline)" if launch.timed_out else f" (exit {launch.exit})")
            )
            if done:
                break
        if done:
            out.units_done += 1
            done_ids.add(nxt.unit_id)
            continue
        out.failed.append(
            {
                "unit_id": nxt.unit_id,
                "kind": nxt.kind,
                "written": len(written),
                "members": len(nxt.members),
            }
        )
        skip.add(nxt.unit_id)
        if out.units_tried == 1 and not written:
            out.stopped = (
                "the first unit wrote nothing in any attempt: the agent cannot judge through "
                "tmap here (run the probe; check the agent's MCP and tool settings)"
            )
            break
    return out
