# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""No tool answer is over the response budget silently.

The page fitters bound the tools that page, but a tool that returns one structured record (an
explanation, a provenance record set, an import table) never passed through them, so an answer of
any size went out unmarked. Two parts:

- one fallback on the MCP call path marks EVERY tool's answer larger than the budget with
  ``over_budget: true`` — measured as the fitters measure it (``json.dumps``' default form, one
  copy, against ``_RESPONSE_BYTE_BUDGET``);
- explain_candidate, whose one growing field is the per-sink summary, withholds summary entries
  from the end back (never the candidate's own callsite) and says which, and how to read them.
"""

from __future__ import annotations

import asyncio
import functools
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_sink_provenance import _addr_ref, _seed
from treasure_map import mcp_app
from treasure_map.mcp_app import _RESPONSE_BYTE_BUDGET

_FUNC = 0x400000
_OWN = 190  # the candidate's own sink: near the end, where withholding starts


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    """One call through the server's own call path, its answer as the client reads it."""
    res = asyncio.run(server.call_tool(name, args))
    blocks = res[0] if isinstance(res, tuple) else res
    payload: dict[str, Any] = json.loads(blocks[0].text)
    return payload


def _sized(size: int, **extra: Any) -> dict[str, Any]:
    """An answer of exactly ``size`` bytes as the budget measures it."""
    out = {**extra, "notice": ""}
    out["notice"] = "x" * (size - len(json.dumps(out)))
    assert len(json.dumps(out)) == size
    return out


def _server_answering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: Callable[[], dict[str, Any]]
) -> Any:
    """The real server (real wrapper, real FastMCP), with legal_notice answering ``answer()``."""
    real = mcp_app.make_tools

    def tools(*a: Any, **k: Any) -> dict[str, Callable[..., Any]]:
        out = real(*a, **k)

        @functools.wraps(out["legal_notice"])
        def legal_notice() -> dict[str, Any]:
            return answer()

        out["legal_notice"] = legal_notice
        return out

    monkeypatch.setattr(mcp_app, "make_tools", tools)
    return mcp_app.build_server(tmp_path / "atlas.db")


# ── the fallback: every answer over the budget is marked, on the server path ─────────────────


def test_an_answer_one_byte_over_the_budget_is_marked_and_one_under_is_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through build_server().call_tool: an answer of _RESPONSE_BYTE_BUDGET + 1 bytes carries
    over_budget: true; one of exactly the budget, or one byte under it, carries no such key.

    MUTATION (verified RED, 1 failed): drop the _mark_over_budget call from the wrapper -> RED.
    MUTATION (verified RED, 1 failed): measure against _RESPONSE_BYTE_BUDGET / 2.5 -> the answer
    one byte under is marked -> RED.
    MUTATION (verified RED, 1 failed): ``>=`` for ``>`` -> the answer at the budget is marked."""
    size = [0]
    server = _server_answering(tmp_path, monkeypatch, lambda: _sized(size[0]))
    size[0] = _RESPONSE_BYTE_BUDGET + 1
    assert _call(server, "legal_notice", {}).get("over_budget") is True
    for within in (_RESPONSE_BYTE_BUDGET, _RESPONSE_BYTE_BUDGET - 1):
        size[0] = within
        out = _call(server, "legal_notice", {})
        assert "over_budget" not in out, within
        assert len(json.dumps(out)) == within  # the answer is exactly what the tool gave


def test_an_answer_that_says_so_already_is_left_as_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool's own over_budget stays (one key, true); an over-budget error answer is marked
    too — the fallback marks, it never cuts or rewrites.

    MUTATION (verified RED): drop the _mark_over_budget call from the wrapper -> RED."""
    answers = iter(
        [
            _sized(_RESPONSE_BYTE_BUDGET + 500, over_budget=True),
            _sized(_RESPONSE_BYTE_BUDGET + 500, error="too much"),
        ]
    )
    server = _server_answering(tmp_path, monkeypatch, lambda: next(answers))
    own = _call(server, "legal_notice", {})
    assert own.get("over_budget") is True and list(own).count("over_budget") == 1
    assert len(own["notice"]) > _RESPONSE_BYTE_BUDGET
    err = _call(server, "legal_notice", {})
    assert err.get("over_budget") is True and err.get("error") == "too much"


def _call_both(server: Any, name: str, args: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    """One call's answer twice, as the client gets it: the text block parsed in its own key
    order, and the structured content."""
    res = asyncio.run(server.call_tool(name, args))
    blocks, structured = res if isinstance(res, tuple) else (res, None)
    text: dict[str, Any] = json.loads(blocks[0].text)
    return text, structured


def test_the_mark_is_the_first_key_of_the_text_and_of_the_structured_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A client that keeps only the head of a long answer still reads the mark: over_budget is
    the FIRST key, in the text block and in the structured content alike, and every other key
    follows in the tool's own order, its value unchanged.

    MUTATION (verified RED, 1 failed): set the mark at the end (``result["over_budget"] = True``
    with no reordering) -> the first key is "error" -> RED."""
    answer = _sized(_RESPONSE_BYTE_BUDGET + 10, error="first", hint="second")
    server = _server_answering(tmp_path, monkeypatch, lambda: dict(answer))
    text, structured = _call_both(server, "legal_notice", {})
    assert next(iter(text)) == "over_budget" and text["over_budget"] is True
    assert list(text)[1:] == list(answer)
    assert {k: text.get(k) for k in answer} == answer
    assert isinstance(structured, dict) and next(iter(structured)) == "over_budget"
    assert list(structured)[1:] == list(answer)


def test_a_tools_own_mark_at_the_end_is_moved_first_and_kept_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool that marked itself last (as a page fitter does) has that mark moved to the front:
    one over_budget key, the rest in order. An answer within the budget is not reordered.

    MUTATION (verified RED, 1 failed): return early when the answer already carries the mark
    -> the mark stays last -> RED."""
    marked = {**_sized(_RESPONSE_BYTE_BUDGET + 10, first="a"), "over_budget": True}
    within = {**_sized(_RESPONSE_BYTE_BUDGET - 100, first="a"), "last": 1}
    answers = iter([dict(marked), dict(within)])
    server = _server_answering(tmp_path, monkeypatch, lambda: next(answers))
    text, _ = _call_both(server, "legal_notice", {})
    assert list(text) == ["over_budget", "first", "notice"]
    assert text.get("over_budget") is True
    text, _ = _call_both(server, "legal_notice", {})
    assert list(text) == list(within) and "over_budget" not in text


# ── explain_candidate: the sink summary is withheld from the end, never the own callsite ─────


def _wide_records(n: int) -> list[dict[str, Any]]:
    """``n`` sink records of one function, each with a dominating writer and its format string
    inlined in the summary (the field that makes a real many-sink summary large)."""
    out = []
    for i in range(n):
        writer = f"snprintf@{hex(_FUNC + 0x10 * i - 4)}"
        out.append(
            {
                "sink_idx": i,
                "sink": "system",
                "sink_addr": hex(_FUNC + 0x10 * i),
                "arg_idx": 0,
                "provenance": {
                    "kind": "stack_buf",
                    "stack_key": f"frame[{i}]",
                    "writer_count": 1,
                    "nearest_dominating_writer": writer,
                    "writers": [
                        {
                            "writer": writer,
                            "dominates_sink": True,
                            "fmt": f"/usr/sbin/tool --opt {i} " + "c" * 300,
                            "varargs": [],
                        }
                    ],
                },
            }
        )
    return out


def _many_sinks(tmp_path: Path, n: int = 200) -> str:
    ref = _addr_ref(_FUNC, _FUNC + 0x10 * _OWN)
    _seed(tmp_path, ref=ref, provenance=_wide_records(n))
    return ref


def test_a_many_sink_explanation_fits_by_withholding_from_the_end(tmp_path: Path) -> None:
    """A function with 200 sink records: the explanation is within the budget and unmarked; the
    summary keeps a prefix plus the candidate's own callsite (flagged); every other entry is
    named, in order, under sink_arg_provenance_summary_withheld — none is lost — and each is read
    in full by the call it names.

    MUTATION (verified RED): return data without _fit_sink_summary -> 138,023 bytes -> RED.
    MUTATION (verified RED): withhold the own callsite like any other entry -> RED.
    MUTATION (verified RED): withhold from the front (the summary reversed first) -> RED."""
    ref = _many_sinks(tmp_path)
    tools = mcp_app.make_tools(tmp_path / "atlas.db")
    out = tools["explain_candidate"](evidence_ref=ref)
    assert out.get("found") is True
    size = len(json.dumps(out))
    assert size <= _RESPONSE_BYTE_BUDGET and "over_budget" not in out
    assert size > _RESPONSE_BYTE_BUDGET - 1_000  # only as much withheld as the budget needs
    summary = out.get("sink_arg_provenance_summary") or []
    kept = [e["sink_idx"] for e in summary]
    withheld = out.get("sink_arg_provenance_summary_withheld") or {}
    held = withheld.get("sink_idx") or []
    assert withheld.get("count") == len(held) > 0
    assert sorted(kept + held) == list(range(200))
    assert kept == [*range(len(kept) - 1), _OWN]  # a prefix, then the own callsite
    assert held == sorted(held) and min(held) == len(kept) - 1
    own = [e for e in summary if e.get("is_candidate_callsite") is True]
    assert [e["sink_idx"] for e in own] == [_OWN]
    read_with = withheld.get("read_with") or ""
    assert read_with.startswith("get_sink_provenance(evidence_ref, sink_idx=")
    full = tools["get_sink_provenance"](evidence_ref=ref, sink_idx=held[-1])
    assert full["record"]["sink_idx"] == held[-1]


def test_a_small_explanation_is_given_whole_with_no_withheld_key(tmp_path: Path) -> None:
    """Twenty sinks fit: every entry is there and the withheld key is absent (not an empty
    one) — an answer within the budget is exactly what it was."""
    ref = _addr_ref(_FUNC, _FUNC + 0x10 * 5)
    _seed(tmp_path, ref=ref, provenance=_wide_records(20))
    out = mcp_app.make_tools(tmp_path / "atlas.db")["explain_candidate"](evidence_ref=ref)
    assert len(json.dumps(out)) <= _RESPONSE_BYTE_BUDGET
    assert "sink_arg_provenance_summary_withheld" not in out and "over_budget" not in out
    assert [e["sink_idx"] for e in out["sink_arg_provenance_summary"]] == list(range(20))


def test_an_explanation_over_the_budget_with_nothing_left_to_withhold_says_so() -> None:
    """Only the own callsite left and still over: it is kept, the withheld entries are named,
    and the answer says it is over (never an empty summary that reads as no sinks).

    MUTATION (verified RED): withhold the own callsite like any other entry -> RED."""
    own = {"sink_idx": 3, "is_candidate_callsite": True, "pad": "x" * 60_000}
    other = {"sink_idx": 4, "is_candidate_callsite": False}
    data = {"found": True, "sink_arg_provenance_summary": (own, other)}
    out = mcp_app._fit_sink_summary(data)
    assert out["sink_arg_provenance_summary"] == [own]
    assert out.get("sink_arg_provenance_summary_withheld", {}).get("sink_idx") == [4]
    assert out.get("over_budget") is True


def test_the_server_marks_an_unpaged_tool_and_fits_the_explanation(tmp_path: Path) -> None:
    """End to end on the real server, two real tools on the same 200-sink function:
    get_sink_provenance without sink_idx (it does not page) answers over the budget and is
    marked by the fallback; explain_candidate answers within it, its summary cut and named.

    MUTATION (verified RED): drop the _mark_over_budget call from the wrapper -> RED.
    MUTATION (verified RED): return data without _fit_sink_summary -> explanation marked -> RED."""
    ref = _many_sinks(tmp_path)
    server = mcp_app.build_server(tmp_path / "atlas.db")
    prov = _call(server, "get_sink_provenance", {"evidence_ref": ref})
    assert len(prov.get("records") or []) == 200
    assert prov.get("over_budget") is True
    ex = _call(server, "explain_candidate", {"evidence_ref": ref})
    assert "over_budget" not in ex
    assert (ex.get("sink_arg_provenance_summary_withheld") or {}).get("count", 0) > 0


# ── the summary fit is linear: one running size, re-measured whole only to confirm ────────────


def _reference_fit(data: dict[str, Any], limit: int) -> dict[str, Any]:
    """The fit by its definition: re-serialize the whole answer before each entry withheld."""
    summary = data.get("sink_arg_provenance_summary")
    if not isinstance(summary, (list, tuple)) or len(json.dumps(data)) <= limit:
        return data
    kept = list(summary)
    held: list[Any] = []
    withheld = {"count": 0, "sink_idx": held, "read_with": mcp_app._SINK_SUMMARY_READ_WITH}
    data["sink_arg_provenance_summary"] = kept
    data["sink_arg_provenance_summary_withheld"] = withheld
    i = len(kept) - 1
    while i >= 0 and len(json.dumps(data)) > limit:
        entry = kept[i]
        if not (isinstance(entry, dict) and entry.get("is_candidate_callsite") is True):
            kept.pop(i)
            held.insert(0, entry.get("sink_idx") if isinstance(entry, dict) else None)
            withheld["count"] = len(held)
        i -= 1
    if not held:
        del data["sink_arg_provenance_summary_withheld"]
    if len(json.dumps(data)) > limit:
        data["over_budget"] = True
    return data


def _synthetic_summary(n: int, own: int | None) -> dict[str, Any]:
    """An answer whose summary entries vary in width (and in the width of their sink_idx), with
    entries that carry no sink_idx and entries that are not objects among them."""
    summary: list[Any] = []
    for i in range(n):
        entry: Any = {
            "sink_idx": i * 37,
            "sink": "system",
            "kind": "stack_buf",
            "fmt": "c" * ((i * 53) % 311),
            "is_candidate_callsite": i == own,
        }
        if i % 17 == 5 and i != own:
            entry = {"note": "x" * (i % 40)}
        elif i % 29 == 7 and i != own:
            entry = "not an object"
        summary.append(entry)
    return {"found": True, "sink_arg_provenance_summary": summary, "pad": "y" * 900}


@pytest.mark.parametrize("n", [1, 2, 9, 10, 11, 120])
def test_the_fit_is_the_one_its_definition_gives(n: int) -> None:
    """Against budgets from tight to just enough, the fitted answer is the one the whole-answer
    re-measuring loop gives, key for key and byte for byte.

    MUTATION (verified RED, the n=120 case): count no separator for an entry withheld (``+ 0``
    for ``+ (2 if len(kept) > 1 else 0)``) -> the running size reads too wide, an entry too many
    is withheld -> RED."""
    for own in (None, 0, n - 1, n // 2):
        whole = len(json.dumps(_synthetic_summary(n, own)))
        for limit in sorted({1, 200, 1_000, 3_000, whole // 2, whole - 1, whole, whole + 1}):
            got = mcp_app._fit_sink_summary(_synthetic_summary(n, own), budget=limit)
            want = _reference_fit(_synthetic_summary(n, own), limit)
            assert list(got) == list(want), (n, own, limit)
            assert json.dumps(got) == json.dumps(want), (n, own, limit)


def test_fitting_a_2000_entry_summary_serializes_a_bounded_multiple_of_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """2,000 entries, most of them withheld: the bytes json.dumps produces while fitting stay
    within a few times the answer's own size (one running size, the whole answer measured only
    to start and to confirm) — not one whole serialization per entry withheld.

    MUTATION (verified RED, 1 failed): re-measure the whole answer before every entry (the
    running size dropped) -> ~485 MB serialized for a ~474 KB answer -> RED."""
    data = _synthetic_summary(2_000, own=3)
    whole = len(json.dumps(data))
    produced = [0]
    real_dumps = json.dumps

    def counting(obj: Any, *a: Any, **k: Any) -> str:
        out = real_dumps(obj, *a, **k)
        produced[0] += len(out)
        return out

    monkeypatch.setattr(mcp_app.json, "dumps", counting)
    out = mcp_app._fit_sink_summary(data)
    monkeypatch.undo()
    held = (out.get("sink_arg_provenance_summary_withheld") or {}).get("count", 0)
    assert held > 1_500
    assert len(json.dumps(out)) <= _RESPONSE_BYTE_BUDGET
    assert produced[0] <= 4 * whole, (produced[0], whole)
