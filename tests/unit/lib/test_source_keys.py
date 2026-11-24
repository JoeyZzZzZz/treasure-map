# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Which KEY a candidate's function asks its binary's own value getter for (F-1), end to end.

Three layers, tested apart and then together:

  * ``value_helpers.helper_keys_called`` — the keys one body passes, as evidence rows;
  * ``data_strings.DataStrings`` — a ``&DAT_<addr>`` key's text, read out of the loaded data
    blocks because such a key has no row in the extracted strings table;
  * the hunt write (``source_keys`` in flow_evidence) and the read (the ``source`` map layer's
    ``evidence``, out through ``explain_candidate``).

Synthetic throughout: ``FUN_<addr>`` is the decompiler's own name for an unnamed function, the
keys are generic field names, and the sinks are standard libc. No run, model or vendor string.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.hunt.data_strings import DataStrings
from treasure_map.lib.hunt.value_helpers import build_helper_tables, helper_keys_called
from treasure_map.lib.pattern.sink_vocabulary import NO_HELPERS, RETURN_SLOT, SourceHelpers
from treasure_map.lib.query.triage import (
    _build_dimensions,
    _source_key_rows,
    state_value_label,
)

from .dispatch_image import RODATA_BASE, Image
from .test_analyzer import _make_db
from .test_value_helpers import _fn

# The keyed-lookup getter the rule admits (see test_value_helpers): it searches its own input, so
# it calls no known source NAME, and writes the field value into its caller's buffer.
_GETTER = (
    "void FUN_00003000(char *param_1,char *param_2,char *param_3){ char *pcVar1; "
    "pcVar1 = strstr(param_1,param_2); if (pcVar1 != (char *)0x0) { strcpy(param_3,pcVar1 + 1); } }"
)
# Two distinct literal keys: what admits the getter into its binary's table.
_KEYED_CALLS = (
    "void keys_fn(char *param_1){ char acStack_40[64]; char acStack_80[64]; "
    'FUN_00003000(param_1,"ssid=",acStack_40); FUN_00003000(param_1,"passwd=",acStack_80); }'
)


def _helpers(*bodies: str) -> SourceHelpers:
    funcs = [_fn(i + 1, _name(b), b) for i, b in enumerate(bodies)]
    tables = build_helper_tables(funcs)
    return next(iter(tables.values())) if tables else NO_HELPERS


def _name(body: str) -> str:
    import re

    m = re.search(r"\b([A-Za-z_]\w*)\s*\(", body[: body.find("{")] if "{" in body else body)
    return m.group(1) if m else "f"


# ── the keys one body passes ────────────────────────────────────────────────────────────────────


def test_the_rows_name_both_key_spellings_and_claim_nothing_about_the_value() -> None:
    """An inline literal and a ``&DAT_<addr>`` pointer are both keys, told apart by ``key_origin``
    so a reader knows which text was read from bytes. ``hops`` is 1 (a direct call), the accessor
    is the getter, ``position`` is the argument index the key sat at, and a data_ref row carries its
    address with ``key`` still None — this layer does not read the database.

    MUTATION (verified RED): collect only string literals -> the data_ref row is gone, and the one
    key the spec's gate 5 needs resolved disappears; drop the de-duplication -> the repeated
    ``"ipVer"`` callsite yields a second identical row."""
    helpers = _helpers(_GETTER, _KEYED_CALLS)
    assert helpers.names == {"FUN_00003000"}
    caller = (
        "void handle(char *param_1){ char acStack_90[128]; "
        "FUN_00003000(param_1,&DAT_00020000,acStack_90); "
        'FUN_00003000(param_1,"ipVer",acStack_90); '
        'FUN_00003000(param_1,"ipVer",acStack_90); system(acStack_90); }'
    )
    rows = helper_keys_called(caller, helpers)
    assert rows == (
        {
            "key": None,
            "key_origin": "data_ref",
            "address": "00020000",
            "accessor": "FUN_00003000",
            "hops": 1,
            "position": 1,
        },
        {
            "key": "ipVer",
            "key_origin": "literal",
            "accessor": "FUN_00003000",
            "hops": 1,
            "position": 1,
        },
    )


def test_a_body_that_calls_no_getter_of_its_binary_carries_no_rows() -> None:
    """Absence is absence: a function that calls none of its binary's getters produces no rows at
    all, rather than a row with an empty key (see the ``_source_key_rows`` docstring).

    MUTATION (verified RED): return a placeholder row per helper name instead of none -> a function
    that never calls one reads as having asked for a key."""
    helpers = _helpers(_GETTER, _KEYED_CALLS)
    plain = 'void plain(void){ char acStack_90[128]; strcpy(acStack_90,"ls"); system(acStack_90); }'
    assert helper_keys_called(plain, helpers) == ()
    assert helper_keys_called(plain, NO_HELPERS) == ()


# ── a data_ref key's text, out of the loaded blocks ─────────────────────────────────────────────


def _blocks_db(path: Path, rows: list[tuple]) -> sqlite3.Connection:
    """A minimal ``data_blocks`` table carrying the columns the reader uses: ``id`` (the per-block
    fetch key the per-lookup path needs) and ``truncated`` (default 0). A row may be a 5-tuple
    ``(binary_id, block_name, start_addr, bytes, initialized)`` or a 6-tuple with ``truncated``."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE data_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, binary_id INT, "
        "block_name TEXT, start_addr TEXT, bytes BLOB, initialized INT, truncated INT DEFAULT 0)"
    )
    conn.executemany(
        "INSERT INTO data_blocks "
        "(binary_id, block_name, start_addr, bytes, initialized, truncated) VALUES (?,?,?,?,?,?)",
        [(row + (0,))[:6] for row in rows],  # default truncated = 0 when a 5-tuple is given
    )
    conn.commit()
    return conn


def test_a_key_reads_out_of_an_initialized_block_and_nothing_else_resolves(
    tmp_path: Path,
) -> None:
    """The read: a NUL-terminated run at the address, from an INITIALIZED block of the right
    binary. Every other case is None — not resolved — never an empty key: an address in no block,
    an address in another binary's block, an uninitialized block, and a block whose start address
    is an overlay spelling the reader cannot place.

    MUTATION (verified RED, per clause): drop the ``initialized = 1`` filter -> the .bss address
    resolves; drop the binary_id filter -> the other binary's key resolves; return "" instead of
    None when no block holds the address -> the unmapped address reads as an empty key; take the
    whole block instead of stopping at the NUL -> the key carries its neighbour's bytes."""
    conn = _blocks_db(
        tmp_path / "blocks.db",
        [
            (1, ".rodata", "0x20000", b"host\x00ipVer\x00", 1),
            (1, ".bss", "0x40000", b"later\x00", 0),
            (2, ".rodata", "0x20000", b"other\x00", 1),
            (1, "overlay", "space::0x50000", b"nope\x00", 1),
        ],
    )
    try:
        reader = DataStrings(conn)
        assert reader.string_at(1, 0x20000) == "host"
        assert reader.string_at(1, 0x20005) == "ipVer"  # stops at its own NUL
        assert reader.string_at(1, 0x40000) is None  # uninitialized
        assert reader.string_at(1, 0x30000) is None  # in no block
        assert reader.string_at(1, 0x50000) is None  # overlay spelling: not placeable
        assert reader.string_at(2, 0x20000) == "other"  # per binary, never pooled
        assert reader.string_at(3, 0x20000) is None  # a binary with no blocks
    finally:
        conn.close()


def test_a_database_without_the_block_table_resolves_nothing_and_does_not_raise(
    tmp_path: Path,
) -> None:
    """An analysis.db built before ``data_blocks`` existed: the reader answers None, so a key stays
    unresolved and visible as such. It never raises — a stale database still hunts.

    MUTATION (verified RED): drop the sqlite_master probe -> ``no such table: data_blocks``."""
    conn = sqlite3.connect(tmp_path / "bare.db")
    try:
        assert DataStrings(conn).string_at(1, 0x20000) is None
    finally:
        conn.close()


# ── the hunt write and the read ─────────────────────────────────────────────────────────────────


def _func(name: str, pc: str, callees: list[str]) -> dict[str, object]:
    return {"name": name, "pseudocode": pc, "hash": f"h_{name}", "callees": callees}


def _hunt_with_keys(tmp_path: Path) -> dict[str, Any]:
    """Hunt one binary whose candidate asks its own getter for two keys — one inline, one a
    ``&DAT_`` pointer whose text sits in the loaded block."""
    image = Image()
    host = image.string("host")
    assert host == RODATA_BASE  # the address the fixture body references
    caller = (
        "void handle(char *param_1){ char acStack_90[128]; "
        f"FUN_00003000(param_1,&DAT_{RODATA_BASE:08x},acStack_90); "
        'FUN_00003000(param_1,"ipVer",acStack_90); '
        'snprintf(acStack_90,0x80,"ping %s",acStack_90); system(acStack_90); }'
    )
    funcs = [
        _func("FUN_00003000", _GETTER, ["strstr", "strcpy"]),
        _func("keys_fn", _KEYED_CALLS, ["FUN_00003000"]),
        _func("handle", caller, ["FUN_00003000", "snprintf", "system"]),
    ]
    d = Path(tempfile.mkdtemp(dir=tmp_path))
    db = _make_db(d, [{"name": "cfgd", "path": "usr/sbin/cfgd", "funcs": funcs, "image": image}])
    atlas = d / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_f1")
    conn = open_atlas(atlas)
    try:
        row = conn.execute(
            "SELECT i.evidence_ref, i.flow_evidence, p.source_class "
            "FROM instance i JOIN pattern p ON p.pattern_id = i.pattern_id "
            "WHERE i.source_anchor = 'handle' AND p.sink_class = 'cmd'"
        ).fetchone()
    finally:
        conn.close()
    return {
        "atlas": atlas,
        "evidence_ref": row[0],
        "flow_evidence": json.loads(row[1] or "{}"),
        "source_class": row[2],
    }


def test_the_hunt_records_the_keys_with_the_data_ref_one_resolved(tmp_path: Path) -> None:
    """The write: ``source_keys`` rides into flow_evidence beside ``source_names``, and the
    ``&DAT_`` key's text is filled in from the loaded block — the resolution the extracted strings
    table cannot supply.

    MUTATION (verified RED, per clause): write no ``source_keys`` key -> no rows; resolve nothing
    (the data-block read returns {}) -> the data_ref row keeps ``key: None`` and the reader never
    learns the field name; resolve against the wrong binary -> the key is None again."""
    got = _hunt_with_keys(tmp_path)
    assert got["source_class"] == "external_input"  # the getter is read as a source
    rows = got["flow_evidence"]["source_keys"]
    assert rows == [
        {
            "key": "host",
            "key_origin": "data_ref",
            "address": f"{RODATA_BASE:08x}",
            "accessor": "FUN_00003000",
            "hops": 1,
            "position": 1,
        },
        {
            "key": "ipVer",
            "key_origin": "literal",
            "accessor": "FUN_00003000",
            "hops": 1,
            "position": 1,
        },
    ]
    # The source NAMES key keeps saying what it always said: the two ride together, neither
    # replacing the other.
    assert got["flow_evidence"]["source_names"] == [{"name": "FUN_00003000", "strength": "weak"}]


def test_the_source_layer_carries_the_keys_as_evidence_and_still_reads_structural(
    tmp_path: Path,
) -> None:
    """The read (the spec's gate 5): both keys reach a reader through ``explain_candidate``, on the
    ``source`` layer's ``evidence``. The layer's own reading does not move — ``structural:param``,
    the same note — because a key is evidence, never a verdict: it must not read as proof that the
    value is controlled.

    MUTATION (verified RED, per clause): drop ``evidence=source_keys`` -> the keys never reach the
    reader; lift the state to ``proven`` when keys are present -> the label changes and a
    structural lead reads as proof."""
    import treasure_map.mcp_app as mcp_app

    got = _hunt_with_keys(tmp_path)
    tools = mcp_app.make_tools(Path(str(got["atlas"])))
    explained = tools["explain_candidate"](str(got["evidence_ref"]))
    assert "error" not in explained
    source = next(d for d in explained["dimensions"] if d["name"] == "source")
    assert source["state"] == "structural" and source["value"] == "param"
    keys = [(r["key"], r["key_origin"]) for r in source["evidence"]]
    assert keys == [("host", "data_ref"), ("ipVer", "literal")]


def test_the_read_side_reads_the_rows_it_is_given_and_absence_as_absence() -> None:
    """``_source_key_rows`` over the stored evidence: a list of objects comes back verbatim, and
    every other stored shape reads as () — the honest absence, which is NOT "no key" (the hunt
    writes the key only when the function asks for one, and a candidate hunted before the key
    existed carries none).

    MUTATION (verified RED): return a one-element tuple holding the raw value when it is not a list
    -> a string or a number reads as a key row and reaches the map layer."""
    rows = [{"key": "host", "key_origin": "data_ref", "accessor": "FUN_1", "hops": 1}]
    assert _source_key_rows({"source_keys": rows}) == tuple(rows)
    assert _source_key_rows({"source_keys": rows + ["junk"]}) == tuple(rows)
    assert _source_key_rows({}) == ()
    assert _source_key_rows(None) == ()
    assert _source_key_rows({"source_keys": "host"}) == ()
    assert _source_key_rows("not json at all") == ()
    assert _source_key_rows(json.dumps({"source_keys": rows})) == tuple(rows)


def test_the_keys_do_not_reach_a_layer_that_is_not_about_the_source() -> None:
    """Scope: the key rows are attached to the ``source`` layer only. A stored key never silently
    becomes evidence for controllability, reachability or any other layer, and it never changes a
    label — so the compact ``state:value`` of every layer is what it was.

    MUTATION (verified RED): attach ``source_keys`` to every dimension -> another layer's evidence
    carries them, and a reader drills into a key under a claim it is not evidence for."""
    rows = [{"key": "host", "key_origin": "literal", "accessor": "FUN_1", "hops": 1}]
    conn = sqlite3.connect(":memory:")
    try:
        kwargs: dict[str, Any] = dict(
            source_class="external_input",
            source_kind="free_string",
            blocking_mechanism=None,
            sink_class="cmd",
            entry_reach="unknown",
            web_triggers=(),
            nvram_key=None,
            sink_anchor=None,
        )
        with_keys = _build_dimensions(conn, flow_evidence={"source_keys": rows}, **kwargs)
        without = _build_dimensions(conn, flow_evidence={}, **kwargs)
    finally:
        conn.close()
    carried = {d.name: d.evidence for d in with_keys if d.evidence}
    assert carried == {"source": tuple(rows)}
    assert [state_value_label(d) for d in with_keys] == [state_value_label(d) for d in without]
    assert [d.note for d in with_keys] == [d.note for d in without]


def test_admitting_a_getter_writes_no_source_kind_here_but_the_charset_layer_still_speaks(
    tmp_path: Path,
) -> None:
    """The recorded reading of the source_kind question, because a precision argument rests on it.

    This feature adds NO ``source_kind`` write of its own. It does not follow that a candidate fed
    by one of these getters keeps ``source_kind`` unknown: once a callee counts as a source, the
    EXISTING charset layer reads the value it hands on as a free string, exactly as it already does
    for the measured rule. So the stored reading is ``free_string`` — the highest charset tier —
    and anything downstream that assumed "no source_kind write" means "no charset lift" is wrong.

    MUTATION (verified RED): admit nothing (the table stays empty) -> source_kind reads unknown and
    the two sides of this test agree."""
    import treasure_map.lib.hunt.value_helpers as vh

    got = _hunt_with_keys(tmp_path)
    assert got["flow_evidence"].get("source_kind") == "free_string"

    # The same binary hunted with the getter unrecognised: the charset layer has nothing to read.
    def _no_tables(funcs: Any) -> dict[int, SourceHelpers]:
        return {}

    real = vh.build_helper_tables
    import treasure_map.lib.hunt.analyzer as analyzer

    real_a2 = analyzer.build_helper_tables
    try:
        vh.build_helper_tables = _no_tables  # type: ignore[assignment]
        analyzer.build_helper_tables = _no_tables  # type: ignore[assignment]
        bare = _hunt_with_keys(tmp_path)
    finally:
        vh.build_helper_tables = real  # type: ignore[assignment]
        analyzer.build_helper_tables = real_a2  # type: ignore[assignment]
    assert bare["source_class"] == "unknown"
    assert bare["flow_evidence"].get("source_kind") == "unknown"
    assert "source_keys" not in bare["flow_evidence"]


# ── M-12: a key is read only from the key argument, told apart from empty / unresolved ────────────


def test_a_key_is_read_only_from_the_key_argument_never_a_default_or_separator() -> None:
    """A getter's other arguments are not keys: the default value a lookup returns when the field is
    absent, and a separator literal, share the callsite but are never the field asked for. A key is
    read only at the helper's key position.

    MUTATION (verified RED): drop the key-position filter -> the default value and the separator
    read as keys the getter was asked for."""
    helpers = SourceHelpers(
        frozenset({("FUN_00005000", RETURN_SLOT)}),
        key_positions=frozenset({("FUN_00005000", 1)}),
    )
    caller = 'void h(char *param_1){ FUN_00005000(param_1,"name","default-value","/"); }'
    assert helper_keys_called(caller, helpers) == (
        {
            "key": "name",
            "key_origin": "literal",
            "accessor": "FUN_00005000",
            "hops": 1,
            "position": 1,
        },
    )


def test_a_getter_with_no_computed_key_position_names_no_key() -> None:
    """A helper whose key position could not be computed (its body compares no parameter) carries no
    rows at all — no anchor, no row — rather than reporting every literal it is passed. This is the
    position filter read from the other side: an empty key-position set matches nothing."""
    helpers = SourceHelpers(frozenset({("FUN_00005000", RETURN_SLOT)}))  # no key_positions
    caller = 'void h(char *param_1){ FUN_00005000(param_1,"name","dflt"); }'
    assert helper_keys_called(caller, helpers) == ()


def test_a_bare_dat_value_is_not_a_key() -> None:
    """Only ``&DAT_<addr>`` (a pointer to the bytes) names a key. A bare ``DAT_<addr>`` is the
    global's VALUE passed by value, not a pointer to a key, so it names no key here.

    MUTATION (verified RED): accept an optional ``&`` -> the by-value global reads as a key."""
    helpers = SourceHelpers(
        frozenset({("FUN_00005000", RETURN_SLOT)}),
        key_positions=frozenset({("FUN_00005000", 1)}),
    )
    assert helper_keys_called("void h(char *p){ FUN_00005000(p,DAT_00020000); }", helpers) == ()
    # the &-prefixed form IS a key (control)
    rows = helper_keys_called("void h(char *p){ FUN_00005000(p,&DAT_00020000); }", helpers)
    assert [r["key_origin"] for r in rows] == ["data_ref"]


def test_an_empty_string_key_is_recorded_as_empty_not_dropped(tmp_path: Path) -> None:
    """``if text is not None`` (not ``if text``): a ``&DAT_`` pointing at an empty string resolves
    to ``""`` and is recorded, so a reader sees a key whose text is empty rather than one that could
    not be read.

    MUTATION (verified RED): ``if text:`` instead -> the empty key is dropped and reads as
    unresolved."""
    from treasure_map.lib.hunt.analyzer import _load_helper_key_strings

    db = tmp_path / "empty.db"
    _blocks_db(db, [(1, ".rodata", "0x20000", b"\x00rest\x00", 1)]).close()
    helpers = SourceHelpers(
        frozenset({("FUN_00005000", RETURN_SLOT)}),
        key_positions=frozenset({("FUN_00005000", 1)}),
    )
    func = _fn(1, "h", "void h(char *p){ FUN_00005000(p,&DAT_00020000); }")
    resolved = _load_helper_key_strings(db, [func], {1: helpers})
    assert resolved == {(1, "00020000"): ""}


def test_a_truncated_block_reads_as_not_resolved(tmp_path: Path) -> None:
    """A truncated block's stored bytes cover LESS than its extent, so a NUL inside them is not
    where the real string ends — such a block reads as None (not resolved), never a key.

    MUTATION (verified RED): drop the truncated filter -> the truncated block resolves a key."""
    conn = _blocks_db(tmp_path / "trunc.db", [(1, ".rodata", "0x20000", b"host\x00", 1, 1)])
    try:
        assert DataStrings(conn).string_at(1, 0x20000) is None
    finally:
        conn.close()
    # the same block not truncated DOES resolve (control)
    ok = _blocks_db(tmp_path / "ok.db", [(1, ".rodata", "0x20000", b"host\x00", 1, 0)])
    try:
        assert DataStrings(ok).string_at(1, 0x20000) == "host"
    finally:
        ok.close()


# ── B-1 丁: every candidate in an admitted helper function reads it as a weak self-source ─────────


def test_every_sink_in_an_admitted_helper_reads_it_as_a_weak_self_source(tmp_path: Path) -> None:
    """End to end: a value-getter helper reads external input (it is why it was admitted), so EVERY
    sink candidate in its body reads the function itself as a weak source — including a copy into a
    LOCAL buffer, not only the one that writes the out-parameter. The getter here copies the parsed
    value into a local stack buffer AND into the caller's buffer; both read external_input. A plain
    function that is not a helper keeps its copy unknown — the lift rests entirely on helper
    membership.

    MUTATION (verified RED by the scratch re-hunt and the classify test): drop the
    ``func_name in helpers.names`` self-source -> the helper's own copies read unknown and the
    getter is left sourceless."""
    # FUN_00409c6c's shape: parse param_1 by key param_2, copy into a local buffer AND the out-param
    getter = (
        "void FUN_00003000(char *param_1,char *param_2,char *param_3){ char acStack_40[64]; "
        "char *pcVar1; pcVar1 = strstr(param_1,param_2); "
        "if (pcVar1 != (char *)0x0) { strcpy(acStack_40,pcVar1); strcpy(param_3,acStack_40); } }"
    )
    plain = "void plain(char *param_1){ char acStack_40[64]; strcpy(acStack_40,param_1); }"
    funcs = [
        _func("FUN_00003000", getter, ["strstr", "strcpy"]),
        _func("keys_fn", _KEYED_CALLS, ["FUN_00003000"]),
        _func("plain", plain, ["strcpy"]),
    ]
    d = Path(tempfile.mkdtemp(dir=tmp_path))
    db = _make_db(d, [{"name": "cfgd", "path": "usr/sbin/cfgd", "funcs": funcs}])
    atlas = d / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_self")
    conn = open_atlas(atlas)
    try:
        rows = [
            (r[0], r[1], json.loads(r[2] or "{}"))
            for r in conn.execute(
                "SELECT i.source_anchor, p.source_class, i.flow_evidence "
                "FROM instance i JOIN pattern p ON p.pattern_id = i.pattern_id "
                "WHERE p.sink_class = 'copy' ORDER BY i.evidence_ref"
            )
        ]
    finally:
        conn.close()
    getter_rows = [r for r in rows if r[0] == "FUN_00003000"]
    plain_rows = [r for r in rows if r[0] == "plain"]
    # BOTH of the getter's copies (local buffer and out-parameter) read external_input + self-source
    assert len(getter_rows) == 2
    for _anchor, sc, ev in getter_rows:
        assert sc == "external_input"
        assert ev["source_names"] == [{"name": "FUN_00003000", "strength": "weak"}]
    # the plain (non-helper) copy stays unknown with no source
    assert plain_rows and all(sc == "unknown" for _a, sc, _e in plain_rows)
    assert all("source_names" not in ev for _a, _sc, ev in plain_rows)
