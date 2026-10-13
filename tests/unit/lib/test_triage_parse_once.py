# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""lib/query/triage reads each candidate's stored flow_evidence through one parse: the map parses a
candidate's evidence once and hands the parsed object to every reader, and no reader changes it.

Synthetic atlas, no analyzer."""

from __future__ import annotations

import copy
import importlib
import json
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import triage

_TRIAGE = importlib.import_module("treasure_map.lib.query.triage")  # the module, not the function


def _pattern(conn: sqlite3.Connection, fp: str, sink_class: str) -> int:
    return upsert_pattern(
        conn,
        source_class="external_input",
        sink_class=sink_class,
        call_sequence_shape="source->...->sink",
        structural_fingerprint=fp,
        fingerprint_algo_version="callseq-v1",
    )


# ── one parse per candidate: every reader is handed the parsed evidence ──────────────────────


def _evidence_corpus(conn: sqlite3.Connection) -> list[str]:
    """Candidates whose evidence reaches every reader of the map (entry sites, source kind, the
    anchor and extraction facts, def-use records, the wrapper markers, dispatch leads, sanitizers,
    a copy length), each with its own evidence text, plus one unparsable and one absent. Returns the
    texts that are present."""
    shapes: list[dict[str, object]] = [
        {
            "entry_reach": {
                "status": "found",
                "sites": [
                    {"kind": "web_endpoint", "method": "POST", "endpoint": "/apply.cgi"},
                    {"kind": "script_call", "script": "/etc/init.d/rcS", "line": 3},
                ],
            },
            "source_kind": "free_string",
            "sink_arg_provenance": [
                {"sink": "system", "sink_addr": "0x1010", "provenance": {"kind": "unresolved"}},
                {"sink": "printf", "provenance": {"kind": "constant", "value": "x"}},
            ],
            "reachability_leads": [{"via": "string_keyed_edge", "key": "mode", "hops": 1}],
            "sanitizer_seen": [{"name": "check_input", "on_path": True}],
        },
        {
            "source_kind": "charset_safe",
            "flow_path": {"sink_via_wrapper": True, "wrapper": {"wrapped_sink": "system"}},
            "callsite_located": False,
            "anchor_degraded": "out_of_body",
        },
        {
            "extraction_current": False,
            "extraction_pass": "older",
            "sink_arg_provenance": [
                {"sink": "system", "provenance": {"kind": "constant", "value": "reboot"}}
            ],
        },
        {"size_kind": "cap_const", "size_flow": {"size_arg": "0x40"}, "trace_boundary": "x"},
    ]
    texts = [json.dumps(s) for s in shapes]
    pid = _pattern(conn, "fp_parse_once", "cmd")
    copy_pid = _pattern(conn, "fp_parse_once_copy", "copy")
    for i, text in enumerate([*texts, "not json", None]):
        add_instance(
            conn,
            InstanceRow(
                pattern_id=copy_pid if i == 3 else pid,
                pseudocode_hash=f"h{i}",
                source_anchor=f"fn{i}",
                sink_anchor="strcpy" if i == 3 else "system",
                source_run_id="run_1",
                reachability_status="unknown",
                provenance_level="L0",
                evidence_ref=f"run_1#fn{i}",
                scope_origin="intra",
                origin="unknown",
                flow_evidence=text,
            ),
        )
    return [*texts, "not json"]


class _CountingJson:
    """The triage module's ``json``, counting each text ``loads`` is handed."""

    def __init__(self) -> None:
        self.parsed: dict[str, int] = {}

    def loads(self, s: str, *a: object, **k: object) -> object:
        self.parsed[s] = self.parsed.get(s, 0) + 1
        return json.loads(s, *a, **k)  # type: ignore[arg-type]

    def __getattr__(self, name: str) -> object:
        return getattr(json, name)


def test_each_candidates_evidence_is_parsed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A large run holds hundreds of MB of evidence, and the map reads a dozen fields of each
    candidate's: it is parsed ONCE per candidate and the parsed object is handed to every reader,
    not re-parsed by each. Every text here is distinct, so a count above one is one candidate's
    evidence parsed again.

    MUTATION: hand ``anchor_facts`` the evidence TEXT in ``_candidate`` (a reader parsing for
    itself) -> those texts count 2 -> RED."""
    mod = _TRIAGE
    conn = open_atlas(tmp_path / "atlas.db")
    texts = _evidence_corpus(conn)
    counting = _CountingJson()
    monkeypatch.setattr(mod, "json", counting)
    assert len(triage(conn)) == len(texts) + 1
    assert counting.parsed == {t: 1 for t in texts}


def test_no_reader_changes_the_evidence_it_is_handed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one parsed evidence is shared by every reader of a candidate, so none may change it: what
    each candidate's parse returned is compared, after the whole map is built, with a copy taken at
    parse time.

    MUTATION: ``data.pop("sanitizer_seen", None)`` in ``_entry_reach_sites`` -> RED."""
    mod = _TRIAGE
    conn = open_atlas(tmp_path / "atlas.db")
    _evidence_corpus(conn)
    seen: list[tuple[object, object]] = []
    real = mod._parse_evidence

    def recording(text: str | None) -> object:
        data = real(text)
        seen.append((data, copy.deepcopy(data)))
        return data

    monkeypatch.setattr(mod, "_parse_evidence", recording)
    triage(conn)
    assert sum(1 for data, _ in seen if data is not None) == 4  # every parsable shape was read
    for data, before in seen:
        assert data == before
