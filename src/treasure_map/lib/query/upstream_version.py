# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Upstream library version of a diffed binary, and the pair review's upstream groups.

A read of facts already extracted (each run's analysis.db ``binaries`` + ``strings``): nothing is
stored, and no code stamp reads this module.

**Identity is the FILE NAME**, read the way the dependency resolver matches names
(``lib/analyze/xrefs._build_soname_map``: ``libssl.so.1.1`` -> ``libssl.so`` -> ``libssl``): a
rule's name pattern is matched against the name with its ``.so`` version suffix and then its
``.so`` dropped. It is NOT ``imports.lib_soname`` — that column names the library each IMPORTED
symbol comes from, not the binary itself. A binary's own DT_SONAME is extracted and stored nowhere;
reading it would be an extraction change (it moves the scan stamp and needs a re-scan), so it is
not used here. Each side of a diff is its own binary, found by its content hash; two binaries of
one name at different paths are therefore two binaries, each reported with its own path.

**The version is what the binary's own strings state**, by a per-library banner rule
(``OpenSSL 1.1.1k ...``). No rule for the library, no string matching a rule, or two different
versions stated by one binary's strings -> ``unknown``, with the reason; a side that could not be
read -> ``unknown`` too. ``unknown`` is not "no version". Only the version is given: no advisory
lookup is made and no reading of the version is offered.

**Upstream groups** (pair review): the pair's diffs whose binaries name the same upstream library,
with the versions each side states as a fact inside the group (one row per A/B version pair,
``unknown`` included), and how many work units each group's diffs hand out. A
navigation annotation only: units, unit ids, ``must_read`` and the must-read set are untouched —
nothing is filtered, demoted or reordered — and belonging to an upstream library is not a safety
proof (a fix in an upstream library is a change like any other).
"""

from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from treasure_map.lib.ro_db import ro_connect

UNKNOWN = "unknown"
GROUPS_SHOWN = 12  # upstream groups listed in the pair report (the rest are counted)
DIFFS_SHOWN = 4  # binaries named per listed group (the rest are counted)
_STRING_CLIP = 80

_V3 = r"(\d+\.\d+\.\d+[a-z]?)"


@dataclass(frozen=True)
class Library:
    """An upstream project: the file names it ships under (``stem`` is fullmatched against the
    name in its unversioned form) and its version banners (``(label, pattern)``, group 1 = the
    version). No banner -> its binaries' versions are ``unknown`` (``no_banner_rule``).
    ``executable_only``: the rule names programs, so a file name carrying ``.so`` never matches."""

    name: str
    stem: str
    banners: tuple[tuple[str, str], ...] = ()
    executable_only: bool = False


# Public upstream projects only; the banners are the projects' own version strings.
LIBRARIES: tuple[Library, ...] = (
    Library("openssl", r"lib(?:crypto|ssl)", (("OpenSSL <v>", r"OpenSSL " + _V3),)),
    Library("sqlite", r"libsqlite3", (("<v> (whole string)", r"^(3\.\d{1,2}\.\d{1,2})$"),)),
    Library(
        "zlib",
        r"libz",
        (
            ("(de|in)flate <v> Copyright", r"(?:de|in)flate (\d+\.\d+\.\d+(?:\.\d+)?) Copyright"),
            ("<v> (whole string)", r"^(1\.2\.\d+(?:\.\d+)?)$"),
        ),
    ),
    Library(
        "curl",
        r"libcurl|curl",
        (("libcurl/<v>", r"libcurl/(\d+\.\d+\.\d+)"), ("<v> (whole string)", r"^(7\.\d+\.\d+)$")),
    ),
    Library("libxml2", r"libxml2", (("<v> (whole string)", r"^(2\.\d+\.\d+)$"),)),
    Library("busybox", r"busybox.*", (("BusyBox v<v>", r"BusyBox v(\d+\.\d+\.\d+)"),)),
    Library(
        "dropbear",
        r"dropbear.*",
        (
            ("dropbear_<v>", r"dropbear_(\d{4}\.\d+)"),
            ("Dropbear ... v<v>", r"Dropbear[^0-9]*v?(\d{4}\.\d+)"),
        ),
    ),
    Library(
        "strongswan",
        r"libstrongswan.*|libcharon.*|charon|starter",
        (("strongSwan <v>", r"strongSwan (\d+\.\d+\.\d+)"),),
    ),
    Library(
        "iproute2",
        r"ip|tc|ss|bridge",
        (("iproute2-<v>", r"iproute2-(?:ss)?([0-9][0-9.]+)"),),
        executable_only=True,
    ),
    Library(
        "uclibc",
        r"(?:lib|ld-)uClibc(?!\+\+).*",
        (("uClibc <v>", r"uClibc(?:-ng)? (\d+\.\d+\.\d+(?:\.\d+)?)"),),
    ),
    Library(
        "glibc",
        r"libc-2\..*|ld-2\..*",
        (("GNU C Library ... version <v>", r"GNU C Library[^\n]*?version (\d+\.\d+)"),),
    ),
    Library("libpcap", r"libpcap", (("libpcap version <v>", r"libpcap version (\d+\.\d+\.\d+)"),)),
    Library("dnsmasq", r"dnsmasq", (("dnsmasq-<v>", r"dnsmasq-(\d+\.\d+)"),)),
    Library(
        "hostapd",
        r"hostapd|wpa_supplicant",
        (("hostapd|wpa_supplicant v<v>", r"(?:hostapd|wpa_supplicant) v(\d+\.\d+)"),),
    ),
    Library("openvpn", r"openvpn", (("OpenVPN <v>", r"OpenVPN (\d+\.\d+\.\d+)"),)),
    Library("lighttpd", r"lighttpd", (("lighttpd/<v>", r"lighttpd/(\d+\.\d+\.\d+)"),)),
    Library(
        "pppd",
        r"pppd",
        (
            ("pppd version <v>", r"pppd version (\d+\.\d+\.\d+)"),
            ("<v> (whole string)", r"^(2\.4\.\d+)$"),
        ),
    ),
    Library("expat", r"libexpat", (("expat_<v>", r"expat_(\d+\.\d+\.\d+)"),)),
    Library(
        "mbedtls",
        r"libmbed.*|libpolarssl.*",
        (("mbed TLS|PolarSSL <v>", r"(?:mbed TLS|PolarSSL) (\d+\.\d+\.\d+)"),),
    ),
    # GLIBCXX_<n> symbol-version tags name ABI levels, not a release: no banner rule.
    Library("libstdcxx", r"libstdc\+\+"),
    Library("json-c", r"libjson-c"),
    Library("libnl", r"libnl.*"),
    Library(
        "iptables",
        r"(?:libiptc|libxtables|libip[46]tc|iptables|xtables-multi).*",
        (("iptables-<v>", r"iptables-(\d+\.\d+\.\d+)"),),
    ),
    Library(
        "samba",
        r"(?:smbd|nmbd|samba_multicall|libsmb).*",
        (("Version <v>", r"Version (\d+\.\d+\.\d+)"),),
    ),
    Library("ncurses", r"libncurses.*", (("ncurses <v>", r"ncurses (\d+\.\d+)"),)),
    Library("pcre", r"libpcre.*"),
    Library(
        "mtd-utils",
        r"mtdinfo|nanddump|ubinfo|nandwrite|flash_erase|ubiattach",
        (("mtd-utils <v>", r"mtd-utils[ -](\d+\.\d+\.\d+)"),),
    ),
    Library("gcc-runtime", r"libgcc_s"),
)

_STEMS = tuple((lib, re.compile(lib.stem)) for lib in LIBRARIES)
_BANNERS = {lib.name: tuple((lbl, re.compile(p)) for lbl, p in lib.banners) for lib in LIBRARIES}


def unversioned_name(name: str) -> str:
    """``libssl.so.1.1`` -> ``libssl``: the dependency resolver's weakest name form (its
    ``.so.N...`` suffix made ``.so``, then ``.so`` dropped); a name without them is itself."""
    base = re.sub(r"\.so(\.\d+)+$", ".so", name)
    return re.sub(r"\.so$", "", base)


def library_of(name: str | None) -> str | None:
    """The upstream library a file name names, or None when no rule's name pattern matches."""
    if not name:
        return None
    base = os.path.basename(name)
    stem = unversioned_name(base)
    shared = stem != base  # the name carried a ``.so`` (versioned or not)
    return next(
        (
            lib.name
            for lib, rx in _STEMS
            if rx.fullmatch(stem) and not (lib.executable_only and shared)
        ),
        None,
    )


def version_of(library: str, values: Iterable[str | None]) -> tuple[str, dict[str, Any]]:
    """``(version, basis)`` from a binary's strings by ``library``'s banner rules. One version
    stated -> it, with the rule and the first string (sorted) stating it; none, or two different
    -> ``unknown`` with the reason."""
    rules = _BANNERS.get(library, ())
    if not rules:
        return UNKNOWN, {"reason": "no_banner_rule"}
    seen: dict[str, tuple[str, str]] = {}
    for value in sorted(v for v in values if v):
        for label, rx in rules:
            m = rx.search(value)
            if m and m.group(1) not in seen:
                seen[m.group(1)] = (label, value)
    if not seen:
        return UNKNOWN, {"reason": "no_banner_string"}
    if len(seen) > 1:
        return UNKNOWN, {"reason": "several_versions", "versions_seen": sorted(seen)[:4]}
    version = min(seen)  # the one version stated
    label, value = seen[version]
    return version, {"rule": label, "string": value[:_STRING_CLIP]}


def _truncated(conn: sqlite3.Connection, bid: int) -> bool:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(binaries)")}
    if "strings_truncated" not in cols:
        return False
    row = conn.execute("SELECT strings_truncated FROM binaries WHERE id = ?", (bid,)).fetchone()
    return row is not None and row[0] == 1


def read_side(
    conn: sqlite3.Connection, sha: str | None, fallback_name: str | None
) -> dict[str, Any]:
    """One diff side: its binary (by content hash, so a same-named binary at another path is never
    read for it), the library its file name names, and the version its strings state.
    ``fallback_name`` (the diff's own binary name) names the library when the side cannot be read;
    its version is then ``unknown`` (``side_unreadable``)."""
    row = None
    if sha:
        row = conn.execute(
            "SELECT id, name, path FROM binaries WHERE sha256 = ?", (sha,)
        ).fetchone()
    if row is None:
        return _unreadable(fallback_name, "the diffed binary is not in that analysis.db")
    bid, name, path = row
    library = library_of(name)
    out: dict[str, Any] = {"path": path or name, "library": library}
    if library is None:
        return out
    values = (v for (v,) in conn.execute("SELECT value FROM strings WHERE binary_id = ?", (bid,)))
    version, basis = version_of(library, values)
    if version == UNKNOWN and basis.get("reason") == "no_banner_string" and _truncated(conn, bid):
        basis["strings_truncated"] = True
    out["version"], out["basis"] = version, basis
    return out


def _unreadable(name: str | None, why: str) -> dict[str, Any]:
    library = library_of(name)
    out: dict[str, Any] = {"path": None, "library": library}
    if library is not None:
        out["version"] = UNKNOWN
        out["basis"] = {"reason": "side_unreadable", "error": why}
    return out


def combine(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """A diff's ``upstream_version``: the library (null when neither side's name names one;
    ``libraries_differ`` when the two sides name different ones) and each side."""
    libs = {s["library"] for s in (a, b) if s.get("library") is not None}
    if not libs:
        return {"library": None}
    out: dict[str, Any] = {"library": libs.pop() if len(libs) == 1 else None}
    if out["library"] is None:
        out["libraries_differ"] = True
    out["a"], out["b"] = a, b
    return out


# ── reading a diff and a pair ────────────────────────────────────────────────────────────────


def _analysis_db(atlas: sqlite3.Connection, run_id: str) -> str | None:
    row = atlas.execute("SELECT analysis_db_path FROM run WHERE run_id = ?", (run_id,)).fetchone()
    return str(row[0]) if row is not None and row[0] else None


def _sides(
    atlas: sqlite3.Connection, run_id: str, wanted: Sequence[tuple[str, str | None, str | None]]
) -> dict[str, dict[str, Any]]:
    """``{diff_id: side}`` for one run's sides of ``wanted`` = ``(diff_id, sha, name)``, the run's
    analysis.db opened once."""
    path = _analysis_db(atlas, run_id)
    if path is None:
        return {d: _unreadable(n, "the run records no analysis.db") for d, _s, n in wanted}
    try:
        conn = ro_connect(path)
    except sqlite3.Error as e:
        return {d: _unreadable(n, f"analysis.db could not be opened: {e}") for d, _s, n in wanted}
    try:
        out = {}
        for diff_id, sha, name in wanted:
            try:
                out[diff_id] = read_side(conn, sha, name)
            except sqlite3.Error as e:
                out[diff_id] = _unreadable(name, f"analysis.db could not be read: {e}")
        return out
    finally:
        conn.close()


_DIFF_COLS = "diff_id, run_a_id, run_b_id, sha256_a, sha256_b, binary_a, binary_b"


def diff_upstream(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any] | None:
    """``upstream_version`` of one diff (None when there is no such diff)."""
    row = atlas.execute(
        f"SELECT {_DIFF_COLS} FROM diff_meta WHERE diff_id = ?",  # noqa: S608
        (diff_id,),
    ).fetchone()
    if row is None:
        return None
    did, run_a, run_b, sha_a, sha_b, bin_a, bin_b = row
    a = _sides(atlas, run_a, [(did, sha_a, bin_a)])[did]
    b = _sides(atlas, run_b, [(did, sha_b, bin_b)])[did]
    return combine(a, b)


def _stat_key(path: str | None) -> tuple[Any, ...]:
    """What a cached reading of ``path`` is keyed by: the file's and its WAL's size and mtime (a
    re-scan rewrites them)."""
    if path is None:
        return (None,)
    key: list[Any] = [path]
    for p in (path, path + "-wal"):
        try:
            st = os.stat(p)
            key += [st.st_size, st.st_mtime_ns]
        except OSError:
            key += [None, None]
    return tuple(key)


_PAIR_CACHE: dict[tuple[Any, ...], dict[str, dict[str, Any]]] = {}
_PAIR_CACHE_MAX = 16


def pair_upstream(atlas: sqlite3.Connection, run_a: str, run_b: str) -> dict[str, dict[str, Any]]:
    """``{diff_id: upstream_version}`` for every diff of the run pair, each run's analysis.db
    opened once; cached by the diff rows and the two analysis.dbs' size and mtime."""
    rows = atlas.execute(
        f"SELECT {_DIFF_COLS} FROM diff_meta WHERE run_a_id = ? AND run_b_id = ? "  # noqa: S608
        "ORDER BY diff_id",
        (run_a, run_b),
    ).fetchall()
    key = (
        tuple(rows),
        _stat_key(_analysis_db(atlas, run_a)),
        _stat_key(_analysis_db(atlas, run_b)),
    )
    cached = _PAIR_CACHE.get(key)
    if cached is not None:
        return cached
    a = _sides(atlas, run_a, [(r[0], r[3], r[5]) for r in rows])
    b = _sides(atlas, run_b, [(r[0], r[4], r[6]) for r in rows])
    out = {r[0]: combine(a[r[0]], b[r[0]]) for r in rows}
    if len(_PAIR_CACHE) >= _PAIR_CACHE_MAX:
        _PAIR_CACHE.clear()
    _PAIR_CACHE[key] = out
    return out


def clear_cache() -> None:
    _PAIR_CACHE.clear()


# ── the pair review's navigation annotation ───────────────────────────────────────────────────


def label(info: dict[str, Any] | None) -> dict[str, Any] | None:
    """A unit's compact upstream label (library and each side's version), or None when its diff's
    binary names no upstream library."""
    if not info or info.get("library") is None:
        return None
    return {
        "library": info["library"],
        "a": (info.get("a") or {}).get("version", UNKNOWN),
        "b": (info.get("b") or {}).get("version", UNKNOWN),
    }


GROUPS_NOTE = (
    "Navigation only: the diffs whose binaries name the same upstream library (by file name), one "
    "group per library; versions lists each A/B version pair its diffs state (by the binary's own "
    "banner strings; unknown = no rule or no string matched, on either side). Units, unit ids and "
    "the must-read set are unchanged, nothing is filtered or reordered; belonging to an upstream "
    "library is not a safety proof, so read each unit as it is handed out."
)


def upstream_rows(
    pair: dict[str, dict[str, Any]],
    units: Iterable[Any],
    disposed: Any,
    binary_of: dict[str, str | None],
    *,
    diffs_shown: int | None = DIFFS_SHOWN,
) -> list[dict[str, Any]]:
    """Every upstream group of the pair, one per library: its diffs (``diff_ids`` and ``binaries``,
    the first ``diffs_shown`` in binary-name order, None = all), the A/B version pairs they state
    (``versions``: each with how many of its diffs state it) and how many units they hand out
    (``units``, ``must_read_units``, ``open_units`` = not yet disposed), the groups handing out the
    most units first. ``units`` are read, never changed; ``disposed(unit)`` says whether one is."""
    by_diff: dict[str, list[Any]] = {}
    for u in units:
        by_diff.setdefault(u.stream, []).append(u)
    groups: dict[str, dict[tuple[str, str], list[str]]] = {}
    for diff_id in sorted(pair):
        lab = label(pair[diff_id])
        if lab is not None:
            groups.setdefault(lab["library"], {}).setdefault((lab["a"], lab["b"]), []).append(
                diff_id
            )

    def name(d: str) -> str:
        return str(binary_of.get(d) or d.rsplit("::", 1)[-1])

    def cut(ids: list[str]) -> list[str]:
        return ids if diffs_shown is None else ids[:diffs_shown]

    rows: list[dict[str, Any]] = []
    for lib, by_version in groups.items():
        diffs = sorted((d for ds in by_version.values() for d in ds), key=lambda d: (name(d), d))
        us = [u for d in diffs for u in by_diff.get(d, [])]
        versions: list[dict[str, Any]] = [
            {"a": va, "b": vb, "diffs": len(ds)} for (va, vb), ds in by_version.items()
        ]
        versions.sort(key=lambda v: (-v["diffs"], v["a"], v["b"]))
        rows.append(
            {
                "library": lib,
                "diffs": len(diffs),
                "diff_ids": cut(diffs),
                "binaries": cut([name(d) for d in diffs]),
                "versions": versions,
                "units": len(us),
                "must_read_units": sum(1 for u in us if u.must_read),
                "open_units": sum(1 for u in us if not disposed(u)),
            }
        )
    # Listed by how many units they hand out (then by name), so a cut keeps the largest; the
    # units themselves keep their own order.
    rows.sort(key=lambda r: (-r["units"], r["library"]))
    return rows


def upstream_groups(
    pair: dict[str, dict[str, Any]],
    units: Iterable[Any],
    disposed: Any,
    binary_of: dict[str, str | None],
) -> dict[str, Any]:
    """The pair report's ``upstream_groups``: the ``GROUPS_SHOWN`` groups of :func:`upstream_rows`
    handing out the most units (each naming its first ``DIFFS_SHOWN`` diffs), the rest counted."""
    rows = upstream_rows(pair, units, disposed, binary_of)
    rest = rows[GROUPS_SHOWN:]
    return {
        "groups_total": len(rows),
        "diffs_in_groups": sum(r["diffs"] for r in rows),
        "groups": rows[:GROUPS_SHOWN],
        "groups_not_shown": len(rest),
        "units_not_shown": sum(r["units"] for r in rest),
        "note": GROUPS_NOTE,
    }
