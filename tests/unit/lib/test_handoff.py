# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The standardized findings hand-off (Design B): the fact/analysis blocks review_report renders,
one per changed_real finding, each with every cell stated (no blanks), neutral section titles and
the standing "awaiting human verification" status."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import DX, World, _pair_anchor, a_row  # noqa: F401
from treasure_map.lib import overlay
from treasure_map.lib.query import review_report as rr

PAIR = "runA::runB"

# Words that would read as a verdict in a tmap-rendered template string (B-6 / acceptance 7). The
# embedded verdict / change_kind / rationale / pseudocode are NOT template strings and not scanned.
_JUDGEMENT_WORDS = {
    "exploit",
    "exploitable",
    "bypass",
    "vulnerable",
    "vulnerability",
    "complete",
    "proven",
    "safe",
    "unsafe",
    "blocked",
}


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    w = World(tmp_path, monkeypatch)
    w.pair(DX, "00001000", "00001000")
    w.rows[DX] = [a_row("00001000")]
    return w


def _stamp() -> rr.HandoffStamp:
    """The same staleness context the CLI builds (installed_commit, the current code stamp)."""
    from treasure_map.lib import rescan_version
    from treasure_map.lib.analyze.ghidra_runner import current_pass_version
    from treasure_map.lib.config.config import load_config
    from treasure_map.version import installed_commit

    return rr.HandoffStamp(
        build_hash=current_pass_version(),
        current=rescan_version.current_code_stamp(load_config()),
        commit=installed_commit(),
    )


def _judge_changed_real(w: World, anchor: str) -> None:
    overlay.annotate_diff(
        w.atlas,
        diff_id=DX,
        anchor_ref=anchor,
        verdict="changed_real",
        rationale="looked at both sides",
        verdict_basis={"change_kind": ["sink_replaced"], "evidence": [anchor]},
        ctx=overlay.WriteContext(channel="mcp", session="s"),
    )


def _fact_cells(block: str) -> list[tuple[str, str]]:
    """The ``- label: value`` fact lines of a block, as (label, value)."""
    out = []
    for line in block.splitlines():
        m = re.match(r"- ([^:]+): (.*)$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def test_a_changed_real_finding_renders_a_block_with_every_cell_stated(world: World) -> None:
    """★ B-2 / B-3: a changed_real finding renders one block — the recorded judgment, the tmap facts
    for its shape, the two analysis placeholders and the status. EVERY fact cell is stated (an
    unavailable one names its reason); none is blank. The status is always "awaiting human
    verification", and tmap emits no reachability/exploitability verdict and never "blocked".

    MUTATION (verified RED): let a fact cell render an empty value -> a blank cell -> RED; drop the
    status line -> RED."""
    anchor = _pair_anchor(DX, "00001000", "00001000")
    _judge_changed_real(world, anchor)
    findings = rr.handoff_findings(world.atlas, PAIR)
    assert len(findings) == 1 and findings[0]["subject_kind"] == "function_pair"
    block = rr.handoff_chunk(world.atlas, PAIR, findings[0], stamp=_stamp())
    assert anchor in block
    cells = dict(_fact_cells(block))
    # the recorded judgment, kept apart from the facts
    assert cells["recorded verdict"] == "changed_real"
    assert cells["recorded change kind"] == "sink_replaced"
    # every fact cell is non-blank; an unavailable one states a reason
    for label, value in _fact_cells(block):
        assert value.strip(), (label, "blank cell")
        if value.startswith("unavailable"):
            assert value != "unavailable ()" and "(" in value, (label, value)
    # the standing status, and no conclusion drawn by tmap
    assert f"status: {rr.HANDOFF_STATUS}" in block
    assert rr.HANDOFF_STATUS == "awaiting human verification"
    assert "blocked" not in block.lower()


@pytest.mark.parametrize(
    ("kind", "anchor", "diff_id"),
    [
        ("function_presence", f"{PAIR}#function_presence#libx::b:00004000", f"{PAIR}::libx"),
        ("non_binary", f"{PAIR}#non_binary#etc/rc", None),
        ("binary_presence", f"{PAIR}#binary_presence#a_only:bin/busybox", None),
    ],
    ids=["presence", "file", "binary_presence"],
)
def test_each_subject_shape_states_every_cell(
    world: World, kind: str, anchor: str, diff_id: str | None
) -> None:
    """★ B-2: the single-side, file and single-binary shapes each render with every fact cell stated
    — "single side", "not applicable (file)" or "not applicable (whole-binary …)" — never a blank.

    MUTATION (verified RED): leave a shape's fact cells unwritten -> a block with no fact line ->
    RED."""
    finding = {
        "anchor_ref": anchor,
        "subject_kind": kind,
        "diff_id": diff_id,
        "verdict": "changed_real",
        "rationale": "r",
        "review_state": "concluded",
        "verdict_basis": {"change_kind": ["restructured"]},
    }
    block = rr.handoff_chunk(world.atlas, PAIR, finding, stamp=_stamp())
    cells = _fact_cells(block)
    labels = {label for label, _ in cells}
    change_labels = {
        "change (tmap facts)",
        "file difference (tmap facts)",
        "whole-binary presence (tmap facts)",
    }
    assert labels & change_labels, labels
    assert "reachable shape (tmap facts)" in labels or "file difference (tmap facts)" in labels
    for _label, value in cells:
        assert value.strip()
    assert f"status: {rr.HANDOFF_STATUS}" in block


def test_the_template_titles_and_labels_carry_no_verdict_word() -> None:
    """★ B-6 / acceptance 7: the structural labels and section titles tmap renders carry no verdict
    word (the embedded judgment / rationale / pseudocode are not scanned). The two analysis titles
    are the neutral ones.

    MUTATION (verified RED): title the hypotheses section 'exploitability' -> RED."""
    assert rr.HANDOFF_HYPOTHESES_TITLE == "agent analysis — unverified hypotheses"
    assert rr.HANDOFF_DEVICE_TITLE == "to check on a device"
    for label in rr._HANDOFF_LABELS:
        words = set(re.findall(r"[a-z]+", label.lower()))
        assert not (words & _JUDGEMENT_WORDS), (label, words & _JUDGEMENT_WORDS)


def test_the_boundary_is_carried_in_every_block(world: World) -> None:
    """★ B-7 / acceptance 14: a block's analysis placeholders carry the boundary — hypotheses and
    checks only, no exploit code / payload / attack steps, status awaiting human verification.

    MUTATION (verified RED): drop the boundary from the block -> RED."""
    for phrase in ("exploit code", "payload", "attack steps", "awaiting human verification"):
        assert phrase in rr.HANDOFF_BOUNDARY, phrase
    anchor = _pair_anchor(DX, "00001000", "00001000")
    _judge_changed_real(world, anchor)
    findings = rr.handoff_findings(world.atlas, PAIR)
    block = rr.handoff_chunk(world.atlas, PAIR, findings[0], stamp=_stamp())
    assert block.count(rr.HANDOFF_BOUNDARY) == 2  # under each analysis placeholder
    assert f"### {rr.HANDOFF_HYPOTHESES_TITLE}" in block
    assert f"### {rr.HANDOFF_DEVICE_TITLE}" in block


# ── the MCP paging tool get_diff_handoff (B-4) ──────────────────────────────────────────────────


def _server_call_on(atlas_path: Path, name: str, args: dict[str, Any]) -> dict[str, Any]:
    from tests.unit.test_tool_surface import _call
    from treasure_map import mcp_app

    return _call(mcp_app.build_server(atlas_path), name, args)


def _wide_findings_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, n: int) -> World:
    w = World(tmp_path, monkeypatch)
    w.rows[DX] = [a_row("00001000")]
    for i in range(1, n + 1):
        addr = f"0000{i}000"
        w.pair(DX, addr, addr)
        anchor = _pair_anchor(DX, addr, addr)
        overlay.annotate_diff(
            w.atlas,
            diff_id=DX,
            anchor_ref=anchor,
            verdict="changed_real",
            rationale="r",
            verdict_basis={"change_kind": ["restructured"], "evidence": [anchor]},
            ctx=overlay.WriteContext(channel="mcp", session="s"),
        )
    return w


def test_the_mcp_pages_concatenate_to_the_cli_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4 / acceptance 5: get_diff_handoff's pages (offset 0 onward) concatenate byte-for-byte
    to the document review_report writes; blocks are in a stable anchor order, paged with no gap
    and no repeat. Here the budget is squeezed so the findings span several pages.

    MUTATION (verified RED): page from a wrong offset (off by one) -> a block repeats or is skipped
    -> the concatenation differs from the document -> RED."""
    from treasure_map import mcp_app

    w = _wide_findings_world(tmp_path, monkeypatch, 5)
    # Effective budget (3_300 - 2_000 = 1_300) fits any one block (max ~1,003) but not two, so the
    # findings span several pages without a single block being truncated.
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 3_300)
    server = mcp_app.build_server(w.path)
    from tests.unit.test_tool_surface import _call

    pages, offsets, off = [], [], 0
    while off is not None:
        r = _call(server, "get_diff_handoff", {"run_pair": PAIR, "offset": off})
        assert "error" not in r, r
        pages.append(r["text"])
        offsets.append(off)
        off = r["next_offset"]
    assert len(offsets) >= 3  # the squeezed budget really paged
    assert offsets == sorted(set(offsets))  # strictly increasing: no repeat, no gap
    mcp_text = "".join(pages)
    document = rr.handoff_document(w.atlas, PAIR, stamp=_stamp())
    assert mcp_text == document


def test_a_single_block_over_budget_is_cut_with_a_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4: a block larger than a page's budget is served cut, with a note saying how much is
    left, rather than dropping it or stalling the paging.

    MUTATION (verified RED): return the block whole when it is over budget -> no cut note -> RED."""
    from treasure_map import mcp_app

    w = _wide_findings_world(tmp_path, monkeypatch, 2)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 300)  # smaller than any one block
    r = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR, "offset": 0})
    assert r["block_truncated"] is True
    assert "truncated" in r["text"]
    assert r["next_offset"] == 1  # paging still advances one block at a time


def test_findings_digest_changes_when_a_judgment_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4: findings_digest moves when a changed_real judgment is written, so a client paging
    across such a write can tell and re-fetch from offset 0.

    MUTATION (verified RED): make the digest a constant -> it never moves -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    first = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR})["findings_digest"]
    addr = "00009000"
    w.pair(DX, addr, addr)
    anchor = _pair_anchor(DX, addr, addr)
    overlay.annotate_diff(
        w.atlas,
        diff_id=DX,
        anchor_ref=anchor,
        verdict="changed_real",
        rationale="r",
        verdict_basis={"change_kind": ["restructured"], "evidence": [anchor]},
        ctx=overlay.WriteContext(channel="mcp", session="s2"),
    )
    second = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR})["findings_digest"]
    assert first != second


def test_a_stale_run_is_refused_not_served_a_skeleton(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4(a) / acceptance 9: get_diff_handoff reads the pair's files through the same stale-run
    gate as the other pair tools — a run produced by provably different code is refused, not served
    a skeleton.

    MUTATION (verified RED): skip the _file_pair_gate call -> a stale pair yields a skeleton ->
    RED."""
    from treasure_map import mcp_app
    from treasure_map.lib.analyze import ghidra_runner

    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    # Build the server against a pass version that the runs (recorded at the real one) cannot match.
    monkeypatch.setattr(ghidra_runner, "current_pass_version", lambda: "STALE-PASS-VERSION")
    monkeypatch.setattr(mcp_app, "_current_pass_version", lambda: "STALE-PASS-VERSION")
    r = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR, "offset": 0})
    assert "text" not in r  # no skeleton
    assert r.get("error") or r.get("stale_scan") or r.get("server"), r


# ── the CLI: review report --handoff (B-4) ──────────────────────────────────────────────────────


def test_the_cli_handoff_file_is_the_mcp_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4(d) / acceptance 5: `review report --handoff -o <file>` writes exactly what
    get_diff_handoff's pages concatenate to — the CLI and the MCP build the same staleness context
    (installed_commit), so the text matches.

    MUTATION (verified RED): give the CLI a different commit than the MCP -> the siblings cells and
    so the files differ -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    w = _wide_findings_world(tmp_path, monkeypatch, 3)
    out_file = tmp_path / "handoff.md"
    res = CliRunner().invoke(
        review_cli.review,
        ["report", PAIR, "--handoff", "-o", str(out_file), "--atlas", str(w.path)],
    )
    assert res.exit_code == 0, res.output
    cli_text = out_file.read_text(encoding="utf-8")
    # concatenate the MCP pages
    pages, off = [], 0
    while off is not None:
        r = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR, "offset": off})
        pages.append(r["text"])
        off = r["next_offset"]
    assert cli_text == "".join(pages)
    assert "3 findings" in res.output


# ── the driver hand-off launch (B-5) ────────────────────────────────────────────────────────────


def test_run_handoff_writes_the_agents_document(tmp_path: Path) -> None:
    """★ B-5: the hand-off launch keeps its full output and the driver reads the finished document
    out of it (claude-code's --output-format json ``result``), writing it to the file — the agent,
    with the file tools off, never writes it.

    MUTATION (verified RED): extract nothing / keep only the tail -> the document is lost -> RED."""
    import json as _json

    from treasure_map.lib import review_driver as rd

    document = "# Findings hand-off\n\n" + ("block\n" * 2000)  # well over the 4000-char tail

    def runner(argv: list[str], *, cwd: Path, timeout: float, keep_full: bool = False) -> rd.Launch:
        assert keep_full is True  # the hand-off launch keeps all output
        return rd.Launch(0, 0.1, False, _json.dumps({"result": document}))

    out_file = tmp_path / "handoff.md"
    res = rd.run_handoff(
        rd.PRESETS["claude-code"],
        atlas_path=tmp_path / "atlas.db",
        run_pair=PAIR,
        workdir=tmp_path,
        out_file=out_file,
        runner=runner,
    )
    assert res["ok"] is True
    assert out_file.read_text(encoding="utf-8") == document


def test_run_handoff_refuses_an_experimental_preset(tmp_path: Path) -> None:
    """★ B-5 / acceptance 15: an experimental preset prints its result another way; the hand-off is
    refused with an error, never a silent empty file.

    MUTATION (verified RED): extract from any preset -> codex silently yields nothing -> RED."""
    from treasure_map.lib import review_driver as rd

    launched = []

    def runner(argv: list[str], *, cwd: Path, timeout: float, keep_full: bool = False) -> rd.Launch:
        launched.append(argv)
        return rd.Launch(0, 0.0, False, "codex output")

    res = rd.run_handoff(
        rd.PRESETS["codex"],
        atlas_path=tmp_path / "atlas.db",
        run_pair=PAIR,
        workdir=tmp_path,
        out_file=tmp_path / "x.md",
        runner=runner,
    )
    assert res["ok"] is False and "experimental" in res["error"]
    assert launched == []  # refused before any launch
    assert not (tmp_path / "x.md").exists()


def test_extract_handoff_reads_only_claude_codes_result() -> None:
    """★ B-5: claude-code's result is extracted; another preset is refused, never a silent miss."""
    from treasure_map.lib import review_driver as rd

    good = rd.Launch(0, 0.0, False, '{"result": "the document"}')
    doc, err = rd.extract_handoff(rd.PRESETS["claude-code"], good)
    assert doc == "the document" and err is None
    doc, err = rd.extract_handoff(rd.PRESETS["codex"], good)
    assert doc is None and err and "experimental" in err
    # claude-code but no JSON result
    doc, err = rd.extract_handoff(rd.PRESETS["claude-code"], rd.Launch(0, 0.0, False, "not json"))
    assert doc is None and err


def test_the_handoff_prompt_carries_the_boundary_and_the_tool() -> None:
    """★ B-7 / acceptance 14: the hand-off prompt tells the agent to read via get_diff_handoff and
    carries the boundary — hypotheses and checks only, no exploit code / payload / attack steps.

    MUTATION (verified RED): drop the boundary from the prompt -> RED."""
    from treasure_map.lib import review_driver as rd

    prompt = rd.handoff_prompt(PAIR)
    assert "get_diff_handoff" in prompt
    for phrase in ("exploit code", "payload", "attack steps", "awaiting human verification"):
        assert phrase in prompt, phrase
    assert "unverified hypotheses" in prompt and "to check on a device" in prompt


def test_run_agent_keep_full_keeps_all_output(tmp_path: Path) -> None:
    """★ B-5: run_agent(keep_full=True) keeps all the output (the per-unit launch keeps only the
    tail); the hand-off launch needs the whole document.

    MUTATION (verified RED): truncate even when keep_full -> RED."""
    import sys

    from treasure_map.lib import review_driver as rd

    argv = [sys.executable, "-c", "print('x' * 5000)"]
    full = rd.run_agent(argv, cwd=tmp_path, timeout=30, keep_full=True)
    assert len(full.output) >= 5000
    tail = rd.run_agent(argv, cwd=tmp_path, timeout=30)
    assert len(tail.output) <= 4000


def test_a_finding_whose_basis_moved_is_marked_not_passed_off_as_current() -> None:
    """★ B-1: a changed_real finding whose basis has moved (review_state not concluded) is marked
    MOVED in the skeleton, so it is not read as a standing conclusion.

    MUTATION (verified RED): render 'current' regardless of review_state -> RED."""
    current = {"review_state": "concluded"}
    moved = {"review_state": "needs_recheck", "basis_state": "basis_moved", "basis_moved": {"x": 1}}
    assert rr._finding_basis_line(current) == "current"
    line = rr._finding_basis_line(moved)
    assert "MOVED" in line and "re-read" in line
