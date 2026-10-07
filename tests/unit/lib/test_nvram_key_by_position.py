# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Reading an nvram key from a getter call by the getter's own key POSITION.

The def-use extractor records a call's constant arguments twice: as ``const_args`` (constants in
order, positions lost) and as ``const_args_by_pos`` (keyed by argument position). For an accessor
whose key is not its first argument — ``nvram_bufget(index, key)`` — the first constant is the
index, and reading it as the key named every such read ``0x0``. The key is now taken at the
position the extractor registry gives for that accessor.

Which calls count as nvram VALUE reads is one set (registry value-returning reads, read-side getter
names, A2 thin wrappers), shared by the key reader and the origin reader so they cannot disagree.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from treasure_map.lib.query.triage import (
    _is_nvram_value_read,
    _nvram_key_from_source,
    _nvram_source_key,
    source_origin,
)


def _cr(callee: str, const_args: list[str], by_pos: dict[str, str] | None = None) -> dict[str, Any]:
    src: dict[str, Any] = {
        "kind": "call_return",
        "callee": callee,
        "const_args": const_args,
        "arg_count": 2,
    }
    if by_pos is not None:
        src["const_args_by_pos"] = by_pos
    return src


def test_the_key_is_read_at_the_accessors_key_position() -> None:
    """nvram_bufget(index, key): argument 1 is the key, argument 0 an index.

    MUTATION (verified RED): read const_args[0] for every accessor (ignore const_args_by_pos) ->
    the key comes back None (the index is a 0x… constant) instead of the key."""
    src = _cr("nvram_bufget", ["0x0", "lan_ipaddr"], {"0": "0x0", "1": "lan_ipaddr"})
    assert _nvram_key_from_source(src) == "lan_ipaddr"


def test_a_non_constant_key_argument_is_no_key() -> None:
    # the index resolved, the key did not: no key, never the index
    assert _nvram_key_from_source(_cr("nvram_bufget", ["0x0"], {"0": "0x0"})) is None


def test_an_index_is_never_a_key_even_on_an_extraction_without_positions() -> None:
    """A record extracted before positions existed falls back to the first constant — and a 0x…
    constant there is an index or a pointer, not a key name."""
    assert _nvram_key_from_source(_cr("nvram_bufget", ["0x0", "lan_ipaddr"])) is None
    assert _nvram_key_from_source(_cr("nvram_get", ["wan_proto"])) == "wan_proto"
    assert _nvram_key_from_source(_cr("nvram_get", ["0x4a10"])) is None


def test_a_composite_key_needs_both_halves_constant() -> None:
    """The pf family keys on prefix + name, joined as the extractor joins them. One half unknown
    is no key; without positions the first constant may be the prefix alone, so also no key.

    MUTATION (verified RED): return the prefix when the name half is missing."""
    both = _cr("nvram_pf_get", ["wl0_", "ssid"], {"0": "wl0_", "1": "ssid"})
    assert _nvram_key_from_source(both) == "wl0_ssid"
    assert _nvram_key_from_source(_cr("nvram_pf_get", ["wl0_"], {"0": "wl0_"})) is None
    assert _nvram_key_from_source(_cr("nvram_pf_get", ["ssid"], {"1": "ssid"})) is None
    assert _nvram_key_from_source(_cr("nvram_pf_get", ["wl0_", "ssid"])) is None


def test_a_value_returning_registry_read_is_now_a_key_source() -> None:
    """nvram_default_get returns the value, so the key it reads reaches the sink — before, only a
    ten-name read-side list was consulted and this key was not seen."""
    assert (
        _nvram_key_from_source(_cr("nvram_default_get", ["wan_proto"], {"0": "wan_proto"}))
        == "wan_proto"
    )


@pytest.mark.parametrize(
    "callee", ["nvram_contains_word", "nvram_is_empty", "nvram_get_bitflag", "nvram_pf_match"]
)
def test_a_predicate_read_is_never_a_value_source(callee: str) -> None:
    """A predicate returns a yes/no about the stored value, not the value: its key does not reach
    the sink.

    MUTATION (verified RED): build the value-read set from every registry read (drop the
    returns_value filter)."""
    src = _cr(callee, ["wan_proto", "x"], {"0": "wan_proto", "1": "x"})
    assert _nvram_key_from_source(src) is None
    assert not _is_nvram_value_read(callee, frozenset())


def test_read_side_getter_names_and_thin_wrappers_keep_working() -> None:
    """Getter names the extractor's list does not carry, and A2 thin wrappers, read the first
    constant as before."""
    assert _nvram_key_from_source(_cr("nvram_safe_get", ["lan_proto"])) == "lan_proto"
    assert _nvram_key_from_source(_cr("cfg_get", ["lan_proto"])) is None
    assert _nvram_key_from_source(_cr("cfg_get", ["lan_proto"]), frozenset({"cfg_get"})) == (
        "lan_proto"
    )
    assert _nvram_key_from_source(_cr("cfg_get", ["0x1"]), frozenset({"cfg_get"})) is None


def _fe(*sources: dict[str, Any]) -> str:
    return json.dumps(
        {
            "sink_arg_provenance": [
                {
                    "sink": "system",
                    "sink_idx": i,
                    "sink_addr": hex(0x100 * (i + 1)),
                    "provenance": s,
                }
                for i, s in enumerate(sources)
            ]
        }
    )


def test_the_candidate_key_and_its_origin_agree_on_what_an_nvram_read_is(tmp_path: Path) -> None:
    """The nvram-source key and the origin list use one predicate: a value-returning registry read
    produces both a key and an nvram origin naming it; a predicate read produces neither.

    MUTATION (verified RED): gate _provenance_origins on NVRAM_GETTERS again -> the
    nvram_default_get origin is missing while the key is reported."""
    from treasure_map.lib.atlas.connection import open_atlas

    conn: sqlite3.Connection = open_atlas(tmp_path / "atlas.db")
    try:
        fe = _fe(_cr("nvram_default_get", ["wan_proto"], {"0": "wan_proto"}))
        assert _nvram_source_key(fe, frozenset(), "system") == "wan_proto"
        origin = source_origin(conn, fe, sink_anchor="system")
        assert origin is not None
        (o,) = origin["origins"]
        assert (o["axis"], o["key"], o["accessor"]) == ("nvram", "wan_proto", "nvram_default_get")

        pred = _fe(_cr("nvram_is_empty", ["wan_proto"], {"0": "wan_proto"}))
        assert _nvram_source_key(pred, frozenset(), "system") is None
        origin = source_origin(conn, pred, sink_anchor="system")
        assert origin is None or all(o["axis"] != "nvram" for o in origin["origins"])
    finally:
        conn.close()
