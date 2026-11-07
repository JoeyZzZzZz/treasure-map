# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The upstream library version of a diffed binary (lib/query/upstream_version, F-2) and the pair
review's upstream groups (F-4), with their MCP faces: get_diff_meta's ``upstream_version``,
list_diffs' ``upstream_library``, start_diff_review(run_pair=...)'s ``report.upstream_groups`` and
a unit's ``upstream`` label.

Zero real data: the World of test_diff_review (one run pair, diffs ``libx`` and ``liby``), whose
binaries are renamed in each run's analysis.db and given synthetic strings."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    DY,
    PAIR,
    SHAS,
    World,
    _clear_view_caches,
)
from tests.unit.lib.test_review_units import _build_world
from treasure_map import mcp_app
from treasure_map.lib.query import review_units as ru
from treasure_map.lib.query import upstream_version as uv


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    uv.clear_cache()
    ru.DIFF_CACHE.clear()


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    return _build_world(tmp_path, monkeypatch)


def _binary(w: World, diff_id: str, side: str, name: str, path: str, strings: list[str]) -> None:
    """Rename ``diff_id``'s binary on ``side`` in that run's analysis.db and give it strings."""
    sha = SHAS[diff_id][0 if side == "a" else 1]
    conn = sqlite3.connect(w.tmp / f"analysis_{side}.db")
    try:
        conn.execute("UPDATE binaries SET name = ?, path = ? WHERE sha256 = ?", (name, path, sha))
        (bid,) = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
        conn.executemany(
            "INSERT INTO strings (binary_id, value, category) VALUES (?, ?, 'misc')",
            [(bid, s) for s in strings],
        )
        conn.commit()
    finally:
        conn.close()
    uv.clear_cache()


LIBCRYPTO = "libcrypto.so.1.1"
NOISE = ["TLSv1.2", "1.1.1", "OpenSSL", "%s version %d.%d"]


def _openssl(w: World, diff_id: str = DX, a: str = "1.1.1k", b: str = "1.1.1t") -> None:
    _binary(w, diff_id, "a", LIBCRYPTO, f"/usr/lib/{LIBCRYPTO}", [*NOISE, f"OpenSSL {a}  1 Jan"])
    _binary(w, diff_id, "b", LIBCRYPTO, f"/usr/lib/{LIBCRYPTO}", [*NOISE, f"OpenSSL {b}  2 Feb"])


# ── F-2: identity by file name, version by banner ───────────────────────────────────────────────


def test_an_openssl_like_library_states_a_different_version_on_each_side(world: World) -> None:
    """★ A binary named like an upstream library (``libcrypto.so.1.1`` -> ``libcrypto``) is that
    library, and each side's version is what its own banner string states — two sides, two
    versions, each with the rule and the string that state it. Through get_diff_meta too.

    MUTATION (verified RED, 1 failed): the OpenSSL banner's version pattern without the letter
    suffix (``_V3`` -> ``(\\d+\\.\\d+\\.\\d+)``) -> both sides read 1.1.1 -> RED."""
    _openssl(world)
    got = uv.diff_upstream(world.atlas, DX)
    assert got is not None and got.get("library") == "openssl", got
    assert got["a"]["version"] == "1.1.1k" and got["b"]["version"] == "1.1.1t", got
    assert got["a"]["basis"] == {"rule": "OpenSSL <v>", "string": "OpenSSL 1.1.1k  1 Jan"}
    assert got["b"]["path"] == f"/usr/lib/{LIBCRYPTO}"
    meta = mcp_app.make_tools(world.path)["get_diff_meta"](diff_id=DX)
    assert meta.get("upstream_version") == got, meta.get("upstream_version")
    other = mcp_app.make_tools(world.path)["get_diff_meta"](diff_id=DY)
    assert other.get("upstream_version") == {"library": None}, other.get("upstream_version")


def test_no_banner_is_unknown_and_the_library_is_still_named(world: World) -> None:
    """★ No string matching a banner rule -> ``unknown`` (``no_banner_string``), even when the
    strings hold version-looking text and the file name carries a ``.so`` version: unknown is not
    guessed into a version (a side whose strings list was cut says so). A library with no rule
    reads ``no_banner_rule``; a side whose run has no analysis.db reads ``side_unreadable``, the
    library still named from the diff's binary.

    MUTATION (verified RED, 1 failed): the unknown fallback replaced by the file name's ``.so``
    version (``return UNKNOWN, {"reason": "no_banner_string"}`` -> ``return "1.1", {...}``) ->
    the version reads 1.1 -> RED.
    MUTATION (verified RED, 1 failed): the OpenSSL banner loosened to any dotted version
    (``r"OpenSSL " + _V3`` -> ``_V3``) -> the noise string "1.1.1" is read as the version -> RED."""
    for side in ("a", "b"):
        _binary(world, DX, side, LIBCRYPTO, f"/usr/lib/{LIBCRYPTO}", NOISE)
    got = uv.diff_upstream(world.atlas, DX)
    assert got is not None and got.get("library") == "openssl", got
    for side in ("a", "b"):
        assert got[side].get("version") == uv.UNKNOWN, got
        assert got[side].get("basis") == {"reason": "no_banner_string"}, got
    conn = sqlite3.connect(world.tmp / "analysis_a.db")
    conn.execute("UPDATE binaries SET strings_truncated = 1 WHERE sha256 = ?", (SHAS[DX][0],))
    conn.commit()
    conn.close()
    uv.clear_cache()
    cut = (uv.diff_upstream(world.atlas, DX) or {}).get("a") or {}
    assert cut.get("basis") == {"reason": "no_banner_string", "strings_truncated": True}, cut
    assert uv.version_of("json-c", ["json-c 0.15"]) == (uv.UNKNOWN, {"reason": "no_banner_rule"})
    two = uv.version_of("openssl", ["OpenSSL 1.1.1k", "OpenSSL 1.0.2u"])
    assert two == (
        uv.UNKNOWN,
        {"reason": "several_versions", "versions_seen": ["1.0.2u", "1.1.1k"]},
    )
    world.atlas.execute("UPDATE run SET analysis_db_path = NULL WHERE run_id = 'runB'")
    world.atlas.execute(
        "UPDATE diff_meta SET binary_b = ? WHERE diff_id = ?", ("libssl.so.1.1", DX)
    )
    world.atlas.commit()
    b = (uv.diff_upstream(world.atlas, DX) or {}).get("b") or {}
    assert b.get("library") == "openssl" and b.get("version") == uv.UNKNOWN, b
    assert (b.get("basis") or {}).get("reason") == "side_unreadable", b


@pytest.mark.parametrize(
    ("name", "want"),
    [
        ("libssl.so.1.1", "openssl"),
        ("libcrypto.so", "openssl"),
        ("libsslvpn.so", None),
        ("libcrypto++.so.8.0.0", None),
        ("busybox", "busybox"),
        ("libnl-genl-3.so.200.20.0", "libnl"),
        ("ld-uClibc-0.9.28.so", "uclibc"),
        ("/usr/sbin/charon", "strongswan"),
        ("libx", None),
    ],
)
def test_identity_is_the_file_name_in_its_unversioned_form(name: str, want: str | None) -> None:
    """The name is matched as the dependency resolver's weakest form (``.so.N`` -> ``.so`` ->
    dropped), and the whole form must match: ``libsslvpn`` is not ``libssl``.

    MUTATION (verified RED, 2 failed): ``rx.fullmatch(stem)`` -> ``rx.match(stem)`` ->
    libsslvpn.so and libcrypto++ read openssl -> RED."""
    assert uv.library_of(name) == want


def test_two_binaries_of_one_name_at_different_paths_are_told_apart(world: World) -> None:
    """★ Two diffs whose binaries share one file name at different paths: each side is read by its
    own content hash, so each diff reports its own path and its own version, and the two land in
    two upstream groups.

    MUTATION (verified RED, 1 failed): read_side looks the binary up by name (``WHERE sha256 = ?``
    -> ``WHERE name = (SELECT name FROM binaries WHERE sha256 = ?) ORDER BY id``) -> the second
    diff reads the first's path and version -> RED."""
    _openssl(world, DX, "1.1.1k", "1.1.1t")
    for side in ("a", "b"):
        _binary(world, DY, side, LIBCRYPTO, f"/opt/app/lib/{LIBCRYPTO}", ["OpenSSL 1.0.2u  x"])
    pair = uv.pair_upstream(world.atlas, "runA", "runB")
    x, y = pair[DX], pair[DY]
    assert (x["a"]["path"], x["a"]["version"]) == (f"/usr/lib/{LIBCRYPTO}", "1.1.1k"), x
    assert (y["a"]["path"], y["a"]["version"]) == (f"/opt/app/lib/{LIBCRYPTO}", "1.0.2u"), y
    assert (y["b"]["path"], y["b"]["version"]) == (f"/opt/app/lib/{LIBCRYPTO}", "1.0.2u"), y
    groups = uv.upstream_groups(pair, [], lambda u: False, {DX: "libx", DY: "liby"})
    keys = [(g["library"], g["a"], g["b"]) for g in groups["groups"]]
    assert sorted(keys) == [("openssl", "1.0.2u", "1.0.2u"), ("openssl", "1.1.1k", "1.1.1t")]


def test_list_diffs_names_the_library_of_an_upstream_row_only(world: World) -> None:
    """list_diffs carries ``upstream_library`` on a row whose binary name names one, and no key on
    the others. (Its name is the diff's binary name: ``libcrypto.so.1.1`` here.)

    MUTATION (verified RED, 1 failed): drop the list_diffs hook -> RED."""
    world.atlas.execute("UPDATE diff_meta SET binary_a = ? WHERE diff_id = ?", (LIBCRYPTO, DX))
    world.atlas.commit()
    out = mcp_app.make_tools(world.path)["list_diffs"](run_a_id="runA", run_b_id="runB")
    rows = {r["diff_id"]: r for r in out["diffs"]}
    assert rows[DX].get("upstream_library") == "openssl", rows[DX]
    assert "upstream_library" not in rows[DY], rows[DY]


# ── F-4: upstream groups, navigation only ─────────────────────────────────────────────────────


def _units(r: ru.PairReview) -> list[tuple[Any, ...]]:
    return [
        (u.unit_id, u.kind, u.must_read, tuple(m.anchor_ref for m in u.members), u.stream)
        for u in r.units
    ]


def _review(w: World) -> ru.PairReview:
    return ru.review_pair(
        w.atlas, "runA", "runB", pair_staleness={"source_stale": False}, server_commit="c0"
    )


FIX = "pair:00001000:00001000"  # libx's A entry: a changed sink call, must-read


def test_an_upstream_entry_that_is_a_real_fix_stays_must_read_after_grouping(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ libx is an upstream library and its A entry is the fix: after the grouping it is still
    in a must-read unit, handed out first, with ``must_read`` unchanged; every unit, its id, kind,
    must_read and members are identical with and without the grouping, and the report is the same
    but for ``upstream_groups``. The group counts the units libx hands out; the note says it is no
    safety proof. End to end through start_diff_review(run_pair=...), within the byte budget.

    MUTATION (verified RED, 1 failed): upstream_groups filters the grouped units out of the
    review's list (``for u in list(units): if label(pair.get(u.stream)): units.remove(u)``)
    -> RED.
    MUTATION (verified RED, 1 failed): upstream_groups demotes them
    (``object.__setattr__(u, "must_read", False)`` for a grouped unit) -> RED."""
    tool = mcp_app.make_tools(world.path)["start_diff_review"]
    plain = _units(_review(world))
    monkeypatch.setattr(uv, "pair_upstream", lambda *a: {})
    without = tool(run_pair=PAIR)
    monkeypatch.undo()
    ru.DIFF_CACHE.clear()
    _openssl(world)
    out = tool(run_pair=PAIR)
    assert "error" not in out, out
    after = _units(_review(world))
    assert after == plain
    fix_units = [u for u in after if any(a.endswith("libx::00001000::00001000") for a in u[3])]
    assert len(fix_units) == 1 and fix_units[0][2] is True, fix_units

    groups = out["report"].get("upstream_groups") or {}
    assert groups.get("groups_total") == 1, groups
    (g,) = groups["groups"]
    libx_units = [u for u in after if u[4] == DX]
    assert libx_units, after
    assert (g["library"], g["a"], g["b"], g["diffs"], g["binaries"]) == (
        "openssl",
        "1.1.1k",
        "1.1.1t",
        1,
        ["libx"],
    ), g
    assert g["units"] == len(libx_units) and g["must_read_units"] == sum(u[2] for u in libx_units)
    assert "not a safety proof" in groups.get("note", ""), groups

    nxt = out["next_unit"]
    assert nxt["members"][0]["entry_id"] == FIX and nxt["must_read"] is True, nxt
    assert nxt.get("upstream") == {"library": "openssl", "a": "1.1.1k", "b": "1.1.1t"}, nxt
    report = {k: v for k, v in out["report"].items() if k != "upstream_groups"}
    assert report == {k: v for k, v in without["report"].items() if k != "upstream_groups"}
    assert without["report"].get("upstream_groups", {}).get("groups") == []
    bare = {k: v for k, v in nxt.items() if k != "upstream"}
    assert bare["unit_id"] == without["next_unit"]["unit_id"]
    assert bare["members"] == without["next_unit"]["members"]
    one = tool(run_pair=PAIR, unit=nxt["unit_id"])
    assert one["unit"].get("upstream") == nxt["upstream"], one["unit"]
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET


def test_the_groups_are_capped_and_the_rest_counted() -> None:
    """The report lists the ``GROUPS_SHOWN`` groups handing out the most units and counts the rest
    (groups and units), so the block stays bounded on a pair with many libraries.

    MUTATION (verified RED, 1 failed): ``rows[:GROUPS_SHOWN]`` -> ``rows`` -> RED."""
    names = [lib.name for lib in uv.LIBRARIES][: uv.GROUPS_SHOWN + 5]
    pair = {f"p::{n}": {"library": n, "a": {"version": "1"}, "b": {"version": "2"}} for n in names}
    units = [
        SimpleNamespace(stream=f"p::{n}", must_read=True)
        for i, n in enumerate(names)
        for _ in range(i)
    ]
    out = uv.upstream_groups(pair, units, lambda u: False, {})
    assert out["groups_total"] == len(names) and len(out["groups"]) == uv.GROUPS_SHOWN, out
    assert out["groups_not_shown"] == 5 and out["units_not_shown"] == sum(range(5)), out
    assert out["groups"][0]["library"] == names[-1] and out["groups"][0]["units"] == len(names) - 1
