# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The non-binary files of two runs, compared by path — computed at read time, stored nowhere.

A version diff (``tmap diff``) compares binaries only. The scan also records the firmware's
non-binary files (``non_binary_files``: shell scripts, config files, credentials, web assets) and a
filtered subset of what they hold (``script_calls``, ``config_entries``, ``credentials``,
``web_endpoints`` / ``web_form_fields``). This module reads both runs' records and says, per path:

  * ``change`` — ``a_only`` / ``b_only`` (the path is recorded on one side only),
    ``content_differs`` (both sides, sha256 differs), ``same``, or ``undetermined`` (a side recorded
    no sha256, so the two cannot be told apart). A row with no path cannot be aligned; it is
    counted apart.
  * a structured comparison per kind, over the recorded rows only — each block says what its table
    records (``recorded_scope``); a multiset difference keeps its ``count``.
  * the text difference of the two files as the firmware root holds them (``hunk``), read only
    inside that root and only when the bytes there are the ones the scan hashed. A credential file,
    a file with a sensitive recorded entry, and a file whose difference holds a private-key header
    or a full crypt hash give the shape of their difference only, never its text.

Credential material and the value of a sensitive config entry are never part of any output, and this
reading computes no hash of them. Every file carries its file-level sha256 (``sha_a`` / ``sha_b``),
as the scan recorded it: when a file's whole content is one credential's material (a single-key PEM
file), that sha256 is also the sha256 of the material. Entry point: a run pair ``{run_a}::{run_b}``,
whether or not a binary diff exists for it. Read-only: the analysis databases are opened read-only
and the firmware roots are only read.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import sqlite3
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.facts import open_analysis_ro
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query.runs import get_run

KINDS = ("shell_script", "config_file", "credential", "web_asset", "kernel_module")
CHANGES = ("a_only", "b_only", "content_differs", "same", "undetermined")
# The changes a page lists by default; ``same`` is counted, and listed only when asked for.
LISTED_CHANGES = ("a_only", "b_only", "content_differs", "undetermined")
DETAILS = ("full", "summary")
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
# A list page's structured lists keep this many items; the file's own page keeps every one.
LIST_PAGE_ITEMS = 10
# A file's own page, in bytes of the JSON encoding the response is measured in: one hunk piece (a
# line, or a part of a longer one), the hunk text (or suppressed shape) of one page, and the
# structured lists of one page. Together with the envelope they stay within the 48,000-byte
# response; when one structured item alone is too large for that, the text beside it takes only
# what is left (file_diff's ``budget``).
HUNK_PIECE_BYTES = 16_000
HUNK_PAGE_BYTES = 28_000
STRUCT_PAGE_BYTES = 12_000
HUNK_CONTEXT = 3

SCOPES = {
    "shell_script": "risk-rule or firmware-binary-launch lines only (script_calls)",
    "config_file": "flag-rule entries only (config_entries)",
    "credential": "parsed credential entries only (credentials); material is compared, never shown",
    "web_asset": (
        "extracted endpoints and editable form fields only (web_endpoints, web_form_fields)"
    ),
}

LEGEND = {
    "change": (
        "per path: a_only / b_only = recorded on one side only; content_differs = both sides, "
        "sha256 differs; same = sha256 equal; undetermined = a side recorded no sha256. A file "
        "with no path cannot be aligned and is counted under unaligned_null_path; a second "
        "record of a path already seen on that side is counted under duplicate_path_rows"
    ),
    "counts_by_kind": (
        "per kind, the files by change; a path whose kind differs between the sides is counted "
        "under its B-side kind and carries kind_a / kind_b"
    ),
    "structured": (
        "a comparison of the rows the scan recorded for the file (recorded_scope says which), as "
        "multiset differences with their count; recorded_rows_same = the sha256 differs but the "
        "recorded rows do not; structured_available names why there is none"
    ),
    "hunk": (
        "the line difference of the two files as the firmware root holds them, with 3 lines of "
        "context; a list page gives hunk_stats only (plus_lines / minus_lines / segments / bytes), "
        "a file's own page (path) gives the text, paged by hunk_offset, and its structured lists "
        "in full, paged by offset (lists_paging); a file on one side only is compared with an "
        "empty file"
    ),
    "hunk_suppressed": (
        "the text is not given, only its shape (each segment's line ranges and its plus_lines / "
        "minus_lines): credential_material = a credential file; sensitive_entry = a side records a "
        "sensitive entry for it; embedded_secret = the difference holds a private-key header or a "
        "full crypt hash"
    ),
    "hunk_unavailable": (
        "why no line difference was read: no_firmware_root, file_missing, file_unreadable, "
        "outside_firmware_root (the path resolves outside the firmware root), "
        "content_differs_from_scan (the bytes on disk are not the ones the scan hashed), "
        "binary_content (a NUL byte), no_scan_hash (a side recorded no sha256), over_size_limit "
        "(the file is larger than this reading reads)"
    ),
    "renamed": (
        "a file subject paired by an equal sha256 under two different paths (the same bytes "
        "moved): one subject, not two one-sided ones; its anchor_ref ends in "
        "{path_a}=>{path_b}, as does a two-path subject paired by a normalised lib/modules "
        "version dir"
    ),
    "paired_by": (
        "how a file's two sides were paired: path (the same path), path_normalized (the same path "
        "but for the lib/modules version-dir segment), sha (an equal sha256: renamed); "
        "sha_ambiguous = a one-sided file whose sha256 several files share, so no rename is "
        "inferred for it"
    ),
    "whole_pair_blocks": (
        "the first page carries ko_changes (the .ko kernel modules, by status, as counts) and "
        "symlink_changes (its lists when small, else counts); ko_offset (from 0, alone) reads "
        "their lists, every list cut at the same item; ko_paging.next_offset continues"
    ),
}

CAVEATS = {
    "recorded_scope": (
        "The sub-tables record a filtered subset of each file: a file with no structured "
        "difference can still differ in lines no rule records — read its hunk."
    ),
    "counts": (
        "A path recorded on one side only is not proof the file was created or deleted: the "
        "ingesters record only the files they recognise, and a file can move."
    ),
}

# A private-key header anywhere in a line (quoted, echoed, inside a string literal), and a crypt
# hash in its complete format — id, an optional rounds= field, salt, hash — not preceded by a word
# character or a ``$``: a regex replacement holding ``$1$`` (``s/$1$abc/``, ``$1$2``) is not one.
_PEM_PRIVATE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_CRYPT_HASH = re.compile(
    r"(?<![\w$])\$(1|2[aby]?|5|6)\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,22}\$[./A-Za-z0-9]{8,}"
)


class FileDiffError(ValueError):
    """A run pair or argument this reading cannot serve, with the message to show."""


# ── the two sides ─────────────────────────────────────────────────────────────────────────


def split_run_pair(atlas: sqlite3.Connection, pair: str) -> tuple[str, str] | None:
    """``(run_a, run_b)`` of a run pair ``{run_a}::{run_b}`` whose two runs this atlas holds, cut
    at the first ``::`` that names two of them (a run id may itself hold ``::``), else None."""
    parts = pair.split("::")
    for cut in range(1, len(parts)):
        run_a, run_b = "::".join(parts[:cut]), "::".join(parts[cut:])
        if get_run(atlas, run_a) is not None and get_run(atlas, run_b) is not None:
            return run_a, run_b
    return None


@dataclass
class _Side:
    """One run's non-binary records, read once."""

    run_id: str
    root: str | None
    files: dict[str, dict[str, Any]]  # path -> its non_binary_files row
    null_path: int
    duplicate_path: int
    rows: dict[str, dict[int, list[dict[str, Any]]]] = field(default_factory=dict)
    # file_inventory: path -> {sha256, size, file_type, inventoried_as, not_inventoried_reason};
    # empty on an analysis.db scanned before file_inventory existed.
    inv: dict[str, dict[str, Any]] = field(default_factory=dict)
    # fs_symlinks: link_path -> {target_raw, target_name, corrupt_reason}; empty on an older db.
    syms: dict[str, dict[str, Any]] = field(default_factory=dict)


_SUB_TABLES = {
    "script_calls": "file_id, command, raw_line, line_number, via",
    "config_entries": "file_id, section, key, value, is_sensitive",
    "credentials": "file_id, cred_type, identifier, algorithm, material, is_sensitive",
    "web_endpoints": "file_id, asset_type, method, path, source",
    "web_form_fields": "file_id, field_keyword",
}


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        is not None
    )


def _read_inventory(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """``file_inventory`` by path: every file the scan saw, ELF and non-binary alike (the full
    ledger). Empty on an analysis.db scanned before the table existed — the reading then falls back
    to the ``non_binary_files`` domain. A path recorded twice keeps the first."""
    if not _has_table(conn, "file_inventory"):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for r in conn.execute(
        "SELECT path, sha256, size, file_type, inventoried_as, not_inventoried_reason "
        "FROM file_inventory WHERE path IS NOT NULL ORDER BY id"
    ):
        row = dict(r)
        out.setdefault(row["path"], row)
    return out


def _read_symlinks(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """``fs_symlinks`` by link_path: the rootfs symbolic links, read-only. Empty on an older db. A
    link_path recorded twice keeps the first."""
    if not _has_table(conn, "fs_symlinks"):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for r in conn.execute(
        "SELECT link_path, target_raw, target_name, corrupt_reason FROM fs_symlinks "
        "WHERE link_path IS NOT NULL ORDER BY id"
    ):
        row = dict(r)
        out.setdefault(row["link_path"], row)
    return out


def _read_side(atlas: sqlite3.Connection, run_id: str) -> _Side:
    run = get_run(atlas, run_id)
    if run is None:
        raise FileDiffError(f"run {run_id!r} is not in this atlas")
    if not run.analysis_db_path:
        raise FileDiffError(f"run {run_id!r} records no analysis.db, so its files cannot be read")
    try:
        conn = open_analysis_ro(run.analysis_db_path)
    except (sqlite3.Error, OSError) as exc:
        raise FileDiffError(f"run {run_id!r}: its analysis.db cannot be opened ({exc})") from exc
    try:
        files: dict[str, dict[str, Any]] = {}
        null_path = duplicate_path = 0
        for r in conn.execute(
            "SELECT id, kind, subtype, name, path, sha256, size_bytes FROM non_binary_files "
            "ORDER BY id"
        ):
            row = dict(r)
            if row["path"] is None:
                null_path += 1
                continue
            if row["path"] in files:  # a path recorded twice: the first row stands, counted
                duplicate_path += 1
                continue
            files[row["path"]] = row
        rows: dict[str, dict[int, list[dict[str, Any]]]] = {}
        # An analysis.db scanned before script_calls.via existed has no such column (this read
        # runs no migration): read it there as NULL, which means literal.
        script_cols = {r[1] for r in conn.execute("PRAGMA table_info(script_calls)")}
        for table, cols in _SUB_TABLES.items():
            if table == "script_calls" and "via" not in script_cols:
                cols = cols.replace(", via", ", NULL AS via")
            by_file: dict[int, list[dict[str, Any]]] = {}
            for r in conn.execute(f"SELECT {cols} FROM {table} ORDER BY id"):  # noqa: S608
                by_file.setdefault(r["file_id"], []).append(dict(r))
            rows[table] = by_file
        inv = _read_inventory(conn)
        syms = _read_symlinks(conn)
    except sqlite3.Error as exc:
        raise FileDiffError(
            f"run {run_id!r}: its non-binary records cannot be read ({exc})"
        ) from exc
    finally:
        conn.close()
    return _Side(run_id, run.firmware_path, files, null_path, duplicate_path, rows, inv, syms)


def _sub(side: _Side, table: str, row: dict[str, Any] | None) -> list[dict[str, Any]]:
    if row is None:
        return []
    return side.rows.get(table, {}).get(row["id"], [])


@dataclass
class PairFiles:
    """Both sides of a run pair and every aligned path, in path order."""

    run_a: str
    run_b: str
    a: _Side
    b: _Side
    paths: list[str]
    hunks: dict[str, Hunk] = field(default_factory=dict)

    def row(self, side: str, path: str) -> dict[str, Any] | None:
        return (self.a if side == "a" else self.b).files.get(path)


def read_pair(atlas: sqlite3.Connection, run_a: str, run_b: str) -> PairFiles:
    a, b = _read_side(atlas, run_a), _read_side(atlas, run_b)
    return PairFiles(run_a, run_b, a, b, sorted(set(a.files) | set(b.files)))


# ── the file-subject domain ─────────────────────────────────────────────────────────────────
#
# An earlier reading aligned the ``non_binary_files`` the ingesters recognised, by exact path. The
# subject domain is now every NON-ELF file of ``file_inventory`` — the no_ingester text and
# binaries too — paired by: exact path, then a normalised lib/modules version-dir segment, then an
# equal sha256 (a rename). ELF files (``elf_*``) are not file subjects: a .ko (et_rel) is an
# information line (``ko_changes``), any other ELF goes through the binary diff / binary_presence.
# The ``non_binary_files`` records still carry the per-file structured comparison and hunk, joined
# by path; a no_ingester file has neither, only its byte hunk and sha256.

STATUSES = ("same", "content_differs", "renamed", "a_only", "b_only", "undetermined")
# A changed subject is one of these — a member of the completion denominator; ``same`` is not.
CHANGED_STATUSES = ("content_differs", "renamed", "a_only", "b_only", "undetermined")
PAIRED_BY = ("path", "path_normalized", "sha")
_MODULES_PREFIX = "lib/modules/"
_MODULE_VER = "\x00"  # internal placeholder for a normalised version-dir segment (never displayed)


def _is_elf(file_type: str | None) -> bool:
    return bool(file_type) and str(file_type).startswith("elf_")


def _is_ko(row: dict[str, Any]) -> bool:
    return _is_elf(row.get("file_type")) and row.get("not_inventoried_reason") == "et_rel"


@dataclass(frozen=True)
class AlignedFile:
    """One file subject of the run pair: the paths it holds on each side (one may be None), how the
    two were paired, the status that pairing gives, and each side's sha256."""

    path_a: str | None
    path_b: str | None
    status: str
    paired_by: str
    sha_a: str | None
    sha_b: str | None
    ingested: bool  # a side has a non_binary_files record (structured comparison + hunk)

    @property
    def path(self) -> str:
        """The one path to read a single-path subject by (both sides share it, or one side holds
        it); for a two-path subject it is ``{path_a}=>{path_b}`` — the anchor key."""
        if self.path_a is not None and self.path_b is not None and self.path_a != self.path_b:
            return f"{self.path_a}=>{self.path_b}"
        return self.path_a if self.path_a is not None else str(self.path_b)

    @property
    def two_path(self) -> bool:
        return self.paired_by in ("path_normalized", "sha") and self.path_a != self.path_b


def _file_domain(side: _Side) -> dict[str, dict[str, Any]]:
    """path -> {sha, file_type, ingested} for every NON-ELF file of one side: file_inventory when
    it holds any (production), else the non_binary_files paths (an older db, or a synthetic fixture
    that records no inventory)."""
    out: dict[str, dict[str, Any]] = {}
    for path, r in side.inv.items():
        if _is_elf(r["file_type"]):
            continue
        out[path] = {
            "sha": r["sha256"],
            "file_type": r["file_type"],
            "ingested": bool(r["inventoried_as"]),
        }
    for path, r in side.files.items():
        if path in out:
            out[path]["ingested"] = True
        else:
            out[path] = {"sha": r["sha256"], "file_type": None, "ingested": True}
    return out


def _module_first_level(paths: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for p in paths:
        if p.startswith(_MODULES_PREFIX):
            seg = p[len(_MODULES_PREFIX) :].split("/", 1)[0]
            if seg:
                out.add(seg)
    return out


def _normalize_active(pf: PairFiles) -> bool:
    """Whether the lib/modules version-dir segment is normalised for this pair: each side has
    EXACTLY ONE first-level directory under ``lib/modules/``, counting files and symlinks together.
    A pair with none, or more than one, on either side does not normalise."""

    def paths(side: _Side) -> set[str]:
        base = side.inv or side.files
        return set(base) | set(side.syms)

    return len(_module_first_level(paths(pf.a))) == 1 and len(_module_first_level(paths(pf.b))) == 1


def _normalize_module_path(p: str) -> str:
    if not p.startswith(_MODULES_PREFIX):
        return p
    rest = p[len(_MODULES_PREFIX) :]
    tail = rest.split("/", 1)
    return _MODULES_PREFIX + _MODULE_VER + (("/" + tail[1]) if len(tail) == 2 else "")


def _status(
    pa: str | None, pb: str | None, sha_a: str | None, sha_b: str | None, paired_by: str
) -> str:
    if pa is not None and pb is not None:
        if paired_by == "sha":
            return "renamed"
        if sha_a is None or sha_b is None:
            return "undetermined"
        return "same" if sha_a == sha_b else "content_differs"
    return "a_only" if pa is not None else "b_only"


def _align(
    da: dict[str, dict[str, Any]], db: dict[str, dict[str, Any]], norm_active: bool
) -> list[AlignedFile]:
    """Pair two sides of one domain (path -> {sha, file_type, ingested}) by exact path, then a
    normalised lib/modules version-dir segment, then an equal sha256 rename. Deterministic;
    ``same`` included. Shared by the file-subject domain and the .ko information line, so both pair
    identically."""
    a_un, b_un = dict(da), dict(db)
    out: list[AlignedFile] = []

    def emit(pa: str | None, pb: str | None, by: str) -> None:
        sha_a = da[pa]["sha"] if pa is not None else None
        sha_b = db[pb]["sha"] if pb is not None else None
        ingested = bool(
            (pa is not None and da[pa]["ingested"]) or (pb is not None and db[pb]["ingested"])
        )
        out.append(
            AlignedFile(pa, pb, _status(pa, pb, sha_a, sha_b, by), by, sha_a, sha_b, ingested)
        )

    # 1. exact path
    for p in sorted(set(a_un) & set(b_un)):
        emit(p, p, "path")
        del a_un[p], b_un[p]
    # 2. normalised lib/modules version-dir segment
    if norm_active:
        bn: dict[str, list[str]] = {}
        for p in b_un:
            bn.setdefault(_normalize_module_path(p), []).append(p)
        for p in sorted(a_un):
            np = _normalize_module_path(p)
            if np != p and bn.get(np):
                bp = sorted(bn[np])[0]
                bn[np].remove(bp)
                emit(p, bp, "path_normalized")
                del a_un[p], b_un[bp]
    # 3. rename by equal sha256 (exactly one each side)
    a_by: dict[str | None, list[str]] = {}
    b_by: dict[str | None, list[str]] = {}
    for p, r in a_un.items():
        a_by.setdefault(r["sha"], []).append(p)
    for p, r in b_un.items():
        b_by.setdefault(r["sha"], []).append(p)
    taken_a: set[str] = set()
    taken_b: set[str] = set()
    for sha in sorted(s for s in set(a_by) & set(b_by) if s is not None):
        la, lb = sorted(a_by[sha]), sorted(b_by[sha])
        if len(la) == 1 and len(lb) == 1:
            emit(la[0], lb[0], "sha")
            taken_a.add(la[0])
            taken_b.add(lb[0])
        else:  # one sha to many files: no unambiguous rename — each stays single-side
            for p in la:
                emit(p, None, "sha_ambiguous")
                taken_a.add(p)
            for p in lb:
                emit(None, p, "sha_ambiguous")
                taken_b.add(p)
    # 4. leftovers, single-side
    for p in sorted(a_un):
        if p not in taken_a:
            emit(p, None, "path")
    for p in sorted(b_un):
        if p not in taken_b:
            emit(None, p, "path")
    return out


def aligned_files(pf: PairFiles) -> list[AlignedFile]:
    """Every NON-ELF file subject of the pair, paired by exact path / normalised version dir /
    equal sha256."""
    return _align(_file_domain(pf.a), _file_domain(pf.b), _normalize_active(pf))


def _ko_domain(side: _Side) -> dict[str, dict[str, Any]]:
    """path -> {sha, file_type, ingested=False} for every .ko (ELF ``et_rel``) of one side."""
    return {
        path: {"sha": r["sha256"], "file_type": r["file_type"], "ingested": False}
        for path, r in side.inv.items()
        if _is_ko(r)
    }


def aligned_ko(pf: PairFiles) -> list[AlignedFile]:
    """Every .ko of the pair, paired as the file subjects are — an information line, not a file
    subject."""
    return _align(_ko_domain(pf.a), _ko_domain(pf.b), _normalize_active(pf))


SYMLINK_NOTE = (
    "Rootfs symbolic links that changed between the two runs, read-only: a link one run holds "
    "alone (a_only / b_only), and a link whose target differs (target_differs). Links paired by "
    "path or by a normalised lib/modules version dir with an unchanged target are not a change and "
    "are not listed. A symbolic link is pure information — it is not a diff subject, has no "
    "direction and is not in the completion denominator."
)


def symlink_changes(pf: PairFiles) -> dict[str, Any]:
    """The run pair's changed symbolic links (one-sided, or whose target differs), paired by exact
    path then a normalised lib/modules version-dir segment, comparing the verbatim target.
    Read-only; not a diff subject and not in the completion denominator."""
    a, b = dict(pf.a.syms), dict(pf.b.syms)
    target_differs: list[dict[str, Any]] = []
    same = 0

    def compare(ea: dict[str, Any], eb: dict[str, Any], **extra: Any) -> None:
        nonlocal same
        if ea["target_raw"] == eb["target_raw"]:
            same += 1
        else:
            target_differs.append(
                {**extra, "target_a": ea["target_raw"], "target_b": eb["target_raw"]}
            )

    for lp in sorted(set(a) & set(b)):
        compare(a.pop(lp), b.pop(lp), link_path=lp)
    if _normalize_active(pf):
        bn: dict[str, list[str]] = {}
        for lp in b:
            bn.setdefault(_normalize_module_path(lp), []).append(lp)
        for lp in sorted(a):
            nlp = _normalize_module_path(lp)
            if nlp != lp and bn.get(nlp):
                blp = sorted(bn[nlp])[0]
                bn[nlp].remove(blp)
                compare(a.pop(lp), b.pop(blp), link_path_a=lp, link_path_b=blp)
    a_only = [{"link_path": lp, "target_raw": a[lp]["target_raw"]} for lp in sorted(a)]
    b_only = [{"link_path": lp, "target_raw": b[lp]["target_raw"]} for lp in sorted(b)]
    return {
        "a_only": a_only,
        "b_only": b_only,
        "target_differs": target_differs,
        "same_count": same,
        "in_denominator": False,
        "note": SYMLINK_NOTE,
    }


# The symbolic-link lists ride the first page while their JSON encoding stays within this; above it
# the first page gives their counts and ko_offset pages them.
SYMLINK_INLINE_BYTES = 4_000
_SYMLINK_LISTS = ("a_only", "b_only", "target_differs")


def symlink_first_page(pf: PairFiles) -> dict[str, Any]:
    """The symlink block of the first page: the whole block when small, else its counts (the lists
    are read with ko_offset) — a whole-pair block never takes the page's budget."""
    block = symlink_changes(pf)
    if len(json.dumps(block)) <= SYMLINK_INLINE_BYTES:
        return block
    out = {k: v for k, v in block.items() if k not in _SYMLINK_LISTS}
    out.update({f"{k}_count": len(block[k]) for k in _SYMLINK_LISTS})
    out["lists_paged_by"] = "ko_offset"
    return out


def whole_pair_page(pf: PairFiles, offset: int, limit: int) -> dict[str, Any]:
    """One ``ko_offset`` page of the whole-pair lists: the .ko modules (content_differs — each one
    parsed —, renamed, undetermined, a_only, b_only) and the symbolic links (a_only, b_only,
    target_differs), every list cut at the same item, as many as fit the page."""
    from treasure_map.lib.query import ko_changes as kc

    groups, same = kc._groups(pf)
    links = symlink_changes(pf)
    lists: dict[str, list[Any]] = {f"ko.{k}": list(v) for k, v in groups.items()}
    lists.update({f"symlink.{k}": links[k] for k in _SYMLINK_LISTS})
    longest = max((len(v) for v in lists.values()), default=0)
    if offset > 0 and offset >= longest:
        raise FileDiffError(f"ko_offset {offset} is past the longest whole-pair list ({longest})")

    def render(key: str, item: Any) -> dict[str, Any]:
        block, name = key.split(".", 1)
        return kc._item(pf, name, item) if block == "ko" else dict(item)

    page, k = kc.paged_lists(lists, offset, limit, kc.KO_PAGE_BYTES, render)
    end = offset + k
    return {
        "ko_changes": {
            "scan_scope": "excluded",
            "same_count": same,
            **{name: page[f"ko.{name}"] for name in groups},
            "totals": {name: len(v) for name, v in groups.items()},
            "note": kc.KO_NOTE,
        },
        "symlink_changes": {
            **{name: page[f"symlink.{name}"] for name in _SYMLINK_LISTS},
            "totals": {name: len(links[name]) for name in _SYMLINK_LISTS},
            "same_count": links["same_count"],
            "in_denominator": False,
            "note": SYMLINK_NOTE,
        },
        "ko_paging": {
            "offset": offset,
            "per_list": k,
            "next_offset": end if end < longest else None,
        },
    }


def change_of(ra: dict[str, Any] | None, rb: dict[str, Any] | None) -> str:
    if rb is None:
        return "a_only"
    if ra is None:
        return "b_only"
    if not ra["sha256"] or not rb["sha256"]:
        return "undetermined"
    return "same" if ra["sha256"] == rb["sha256"] else "content_differs"


def _kind_fields(ra: dict[str, Any] | None, rb: dict[str, Any] | None) -> dict[str, Any]:
    if ra is not None and rb is not None and ra["kind"] != rb["kind"]:
        return {"kind_a": ra["kind"], "kind_b": rb["kind"]}
    return {"kind": (rb or ra or {}).get("kind")}


def _kind_counted(ra: dict[str, Any] | None, rb: dict[str, Any] | None) -> str:
    return str((rb or ra or {}).get("kind"))


def counts_by_kind(pf: PairFiles) -> dict[str, Any]:
    """Per kind, the aligned files by change, with the totals and the rows with no path."""
    by_kind: dict[str, dict[str, int]] = {}
    total = dict.fromkeys(CHANGES, 0)
    for path in pf.paths:
        ra, rb = pf.row("a", path), pf.row("b", path)
        change = change_of(ra, rb)
        kind = _kind_counted(ra, rb)
        by_kind.setdefault(kind, dict.fromkeys(CHANGES, 0))[change] += 1
        total[change] += 1
    ordered = {k: by_kind[k] for k in (*KINDS, *sorted(set(by_kind) - set(KINDS))) if k in by_kind}
    return {
        "counts_by_kind": ordered,
        "counts": total,
        "unaligned_null_path": {"a": pf.a.null_path, "b": pf.b.null_path},
        "duplicate_path_rows": {"a": pf.a.duplicate_path, "b": pf.b.duplicate_path},
    }


# ── structured comparison ─────────────────────────────────────────────────────────────────


def _multiset_delta(
    a_keys: Iterable[Any], b_keys: Iterable[Any]
) -> tuple[Counter[Any], Counter[Any]]:
    ca, cb = Counter(a_keys), Counter(b_keys)
    return ca - cb, cb - ca


def _one_per_line(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One record per source line: a line that launches two binaries is stored as two rows, and
    is still one line of the script. The first row stands (its command and via)."""
    out: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for r in rows:
        if r["line_number"] in seen:
            continue
        seen.add(r["line_number"])
        out.append(r)
    return out


def _script_block(rows_a: list[dict[str, Any]], rows_b: list[dict[str, Any]]) -> dict[str, Any]:
    # ★ Merged by line number FIRST, then counted by text as a multiset: the same text on two
    # lines is two occurrences, and a line one side has once more is a difference. Deduping by
    # text alone would read that extra occurrence as no change.
    rows_a, rows_b = _one_per_line(rows_a), _one_per_line(rows_b)

    def key(r: dict[str, Any]) -> str:
        return (r["raw_line"] or r["command"] or "").strip()

    def items(rows: list[dict[str, Any]], only: Counter[str]) -> list[dict[str, Any]]:
        out, seen = [], set()
        for r in rows:
            k = key(r)
            if k in only and k not in seen:
                seen.add(k)
                out.append(
                    {
                        "command": r["command"],
                        "via": r.get("via") or "literal",
                        "raw_line": k,
                        "line_number": r["line_number"],
                        "count": only[k],
                    }
                )
        return out

    a_only, b_only = _multiset_delta(map(key, rows_a), map(key, rows_b))
    return {"commands_a_only": items(rows_a, a_only), "commands_b_only": items(rows_b, b_only)}


def _config_block(rows_a: list[dict[str, Any]], rows_b: list[dict[str, Any]]) -> dict[str, Any]:
    def grouped(rows: list[dict[str, Any]]) -> dict[tuple[Any, Any], list[dict[str, Any]]]:
        out: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
        for r in rows:
            out.setdefault((r["section"], r["key"]), []).append(r)
        return out

    ga, gb = grouped(rows_a), grouped(rows_b)
    a_only: list[dict[str, Any]] = []
    b_only: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    for sk in sorted(set(ga) | set(gb), key=lambda k: (str(k[0]), str(k[1]))):
        va, vb = ga.get(sk, []), gb.get(sk, [])
        section, key = sk
        if len(va) > len(vb):
            a_only.append({"section": section, "key": key, "count": len(va) - len(vb)})
        elif len(vb) > len(va):
            b_only.append({"section": section, "key": key, "count": len(vb) - len(va)})
        n = min(len(va), len(vb))
        if n == 0:
            continue
        values_a = sorted(str(r["value"]) for r in va[:n])
        values_b = sorted(str(r["value"]) for r in vb[:n])
        if values_a == values_b:
            continue
        item: dict[str, Any] = {"section": section, "key": key}
        sensitive = any(r["is_sensitive"] for r in (*va, *vb))
        if sensitive or n > 1:
            item["value_changed"] = True
        else:
            item["value"] = [va[0]["value"], vb[0]["value"]]
        changed.append(item)
    return {"keys_a_only": a_only, "keys_b_only": b_only, "keys_changed": changed}


def _credential_block(rows_a: list[dict[str, Any]], rows_b: list[dict[str, Any]]) -> dict[str, Any]:
    """Per (cred_type, algorithm): by identifier when every identifier is non-empty and unique on
    each side, else as a multiset of rows. Material is compared here and never returned."""

    def grouped(rows: list[dict[str, Any]]) -> dict[tuple[Any, Any], list[dict[str, Any]]]:
        out: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
        for r in rows:
            out.setdefault((r["cred_type"], r["algorithm"]), []).append(r)
        return out

    def unique_ids(rows: list[dict[str, Any]]) -> bool:
        ids = [r["identifier"] for r in rows]
        return all(ids) and len(set(ids)) == len(ids)

    ga, gb = grouped(rows_a), grouped(rows_b)
    groups: list[dict[str, Any]] = []
    for gk in sorted(set(ga) | set(gb), key=lambda k: (str(k[0]), str(k[1]))):
        va, vb = ga.get(gk, []), gb.get(gk, [])
        group: dict[str, Any] = {"cred_type": gk[0], "algorithm": gk[1]}
        if unique_ids(va) and unique_ids(vb):
            ma = {r["identifier"]: r["material"] for r in va}
            mb = {r["identifier"]: r["material"] for r in vb}
            group["identifiers_a_only"] = sorted(set(ma) - set(mb))
            group["identifiers_b_only"] = sorted(set(mb) - set(ma))
            group["identifiers_changed"] = [
                {"identifier": i, "material_changed": True}
                for i in sorted(set(ma) & set(mb))
                if ma[i] != mb[i]
            ]
            if (
                not any(group[k] for k in ("identifiers_a_only", "identifiers_b_only"))
                and not group["identifiers_changed"]
            ):
                continue
        else:
            only_a, only_b = _multiset_delta(
                (r["material"] for r in va), (r["material"] for r in vb)
            )
            if not only_a and not only_b:
                continue
            group.update(
                {
                    "identity_not_unique": True,
                    "rows_a": len(va),
                    "rows_b": len(vb),
                    "rows_only_a": sum(only_a.values()),
                    "rows_only_b": sum(only_b.values()),
                }
            )
        groups.append(group)
    return {"groups": groups}


def _web_block(
    ep_a: list[dict[str, Any]],
    ep_b: list[dict[str, Any]],
    ff_a: list[dict[str, Any]],
    ff_b: list[dict[str, Any]],
) -> dict[str, Any]:
    cols = ("asset_type", "method", "path", "source")

    def ep_key(r: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(r[c] for c in cols)

    ea, eb = _multiset_delta(map(ep_key, ep_a), map(ep_key, ep_b))
    fa, fb = _multiset_delta((r["field_keyword"] for r in ff_a), (r["field_keyword"] for r in ff_b))

    def eps(only: Counter[tuple[Any, ...]]) -> list[dict[str, Any]]:
        return [
            {**dict(zip(cols, k, strict=True)), "count": n}
            for k, n in sorted(only.items(), key=lambda kv: json.dumps(kv[0]))
        ]

    def fields(only: Counter[Any]) -> list[dict[str, Any]]:
        return [
            {"field_keyword": k, "count": n}
            for k, n in sorted(only.items(), key=lambda kv: str(kv[0]))
        ]

    return {
        "endpoints_a_only": eps(ea),
        "endpoints_b_only": eps(eb),
        "form_fields_a_only": fields(fa),
        "form_fields_b_only": fields(fb),
    }


_LISTS = {
    "shell_script": ("commands_a_only", "commands_b_only"),
    "config_file": ("keys_a_only", "keys_b_only", "keys_changed"),
    "credential": ("groups",),
    "web_asset": (
        "endpoints_a_only",
        "endpoints_b_only",
        "form_fields_a_only",
        "form_fields_b_only",
    ),
}


def structured(pf: PairFiles, path: str) -> dict[str, Any]:
    """The structured comparison of one path's recorded rows (see the module docstring)."""
    ra, rb = pf.row("a", path), pf.row("b", path)
    kind = (rb or ra or {}).get("kind")
    if ra is not None and rb is not None and ra["kind"] != rb["kind"]:
        return {"structured_available": "kind_differs"}
    if kind not in SCOPES:
        return {"structured_available": "no_ingester"}
    if kind == "web_asset":
        sides = [
            (_sub(pf.a, "web_endpoints", ra), _sub(pf.a, "web_form_fields", ra)),
            (_sub(pf.b, "web_endpoints", rb), _sub(pf.b, "web_form_fields", rb)),
        ]
        n_a, n_b = (len(e) + len(f) for e, f in sides)
        block = _web_block(sides[0][0], sides[1][0], sides[0][1], sides[1][1])
    else:
        table = {"shell_script": "script_calls", "config_file": "config_entries"}.get(
            kind, "credentials"
        )
        rows_a, rows_b = _sub(pf.a, table, ra), _sub(pf.b, table, rb)
        n_a, n_b = len(rows_a), len(rows_b)
        make = {
            "shell_script": _script_block,
            "config_file": _config_block,
            "credential": _credential_block,
        }[kind]
        block = make(rows_a, rows_b)
    out: dict[str, Any] = {"recorded_scope": SCOPES[kind], "recorded_rows": {"a": n_a, "b": n_b}}
    if n_a == 0 and n_b == 0:
        out["structured_available"] = "no_recorded_rows"
        if kind == "config_file":
            out["no_recorded_entries"] = True
        return out
    out.update(block)
    if not any(block[k] for k in _LISTS[kind]):
        out["recorded_rows_same"] = True
    return out


def structured_counts(block: dict[str, Any]) -> dict[str, int]:
    """A structured block as counts: each list's summed ``count`` (its length when it has none)."""
    out: dict[str, int] = {}
    for name in sorted({n for names in _LISTS.values() for n in names}):
        items = block.get(name)
        if isinstance(items, list) and items:
            out[name] = sum(int(i.get("count", 1)) for i in items)
    return out


def _cut_lists(block: dict[str, Any], keep: int) -> dict[str, Any]:
    out = dict(block)
    cut: dict[str, int] = {}
    for names in _LISTS.values():
        for name in names:
            items = out.get(name)
            if isinstance(items, list) and len(items) > keep:
                cut[name] = len(items)
                out[name] = items[:keep]
    if cut:
        out["lists_cut"] = {
            "shown": keep,
            "totals": cut,
            "read_all_with": "path (its lists paged by offset)",
        }
    return out


def structured_page(block: dict[str, Any], offset: int, limit: int) -> dict[str, Any]:
    """A file's structured block with each list cut to items ``offset`` .. ``offset + k``: ``k`` at
    most ``limit``, and the largest that keeps the block within STRUCT_PAGE_BYTES (always one).
    ``lists_paging`` says where the cut is and where the next page starts."""
    names = [n for ns in _LISTS.values() for n in ns if isinstance(block.get(n), list)]
    longest = max((len(block[n]) for n in names), default=0)
    if longest == 0:
        if offset > 0:
            raise FileDiffError(f"offset {offset} is past this file's structured lists (none)")
        return block
    if offset >= longest:
        raise FileDiffError(f"offset {offset} is past this file's longest list ({longest} items)")

    def cut(k: int) -> dict[str, Any]:
        out = dict(block)
        for n in names:
            out[n] = block[n][offset : offset + k]
        return out

    lo, hi = 1, max(1, min(limit, longest - offset))
    while lo < hi:  # the largest k whose block fits; the size grows with k
        mid = (lo + hi + 1) // 2
        if len(json.dumps(cut(mid))) <= STRUCT_PAGE_BYTES:
            lo = mid
        else:
            hi = mid - 1
    out = cut(lo)
    end = offset + lo
    out["lists_paging"] = {
        "offset": offset,
        "per_list": lo,
        "totals": {n: len(block[n]) for n in names},
        "next_offset": end if end < longest else None,
    }
    return out


# ── the text difference ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Hunk:
    """One path's line difference: its lines (no file headers), or why there are none."""

    lines: list[str] | None
    unavailable: str | None = None
    suppressed: str | None = None

    def stats(self) -> dict[str, int]:
        assert self.lines is not None
        return {
            "plus_lines": sum(1 for x in self.lines if x.startswith("+")),
            "minus_lines": sum(1 for x in self.lines if x.startswith("-")),
            "segments": sum(1 for x in self.lines if x.startswith("@@")),
            "bytes": len("\n".join(self.lines).encode()),
        }

    def shape(self) -> list[dict[str, Any]]:
        """Each segment's ``@@`` line and its plus / minus line counts — no text."""
        assert self.lines is not None
        out: list[dict[str, Any]] = []
        for x in self.lines:
            if x.startswith("@@"):
                out.append({"range": x, "plus_lines": 0, "minus_lines": 0})
            elif out and x.startswith("+"):
                out[-1]["plus_lines"] += 1
            elif out and x.startswith("-"):
                out[-1]["minus_lines"] += 1
        return out


# Above this a file's line difference is not read (``over_size_limit``) — the same bound the .ko
# reading keeps, so the process's memory never follows a file's size.
MAX_READ_BYTES = 32 * 1024 * 1024
_READ_CHUNK = 1 << 20


def _read_file(root: str | None, path: str, sha: str | None) -> tuple[list[str] | None, str | None]:
    """``(lines, None)`` of one side's file under its firmware root, or ``(None, why)``. Read in
    chunks and hashed as it is read, never past MAX_READ_BYTES (``over_size_limit``)."""
    if not root:
        return None, "no_firmware_root"
    if not sha:
        return None, "no_scan_hash"
    base = os.path.realpath(root)
    real = os.path.realpath(os.path.join(root, path))
    if real != base and not real.startswith(base + os.sep):
        return None, "outside_firmware_root"
    if not os.path.lexists(os.path.join(root, path)) or not os.path.exists(real):
        return None, "file_missing"
    try:
        if os.path.getsize(real) > MAX_READ_BYTES:
            return None, "over_size_limit"
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        read = 0
        with open(real, "rb") as fh:
            while chunk := fh.read(_READ_CHUNK):
                read += len(chunk)
                if read > MAX_READ_BYTES:  # grew since the size was read
                    return None, "over_size_limit"
                digest.update(chunk)
                chunks.append(chunk)
    except OSError:
        return None, "file_unreadable"
    data = b"".join(chunks)
    if digest.hexdigest() != sha.lower():
        return None, "content_differs_from_scan"
    if b"\0" in data:
        return None, "binary_content"
    return data.decode("utf-8", errors="replace").splitlines(), None


def _sensitive(pf: PairFiles, path: str) -> bool:
    for side in (pf.a, pf.b):
        row = side.files.get(path)
        for table in ("config_entries", "credentials"):
            if any(r["is_sensitive"] for r in _sub(side, table, row)):
                return True
    return False


def _embedded_secret(lines: list[str]) -> bool:
    """Whether any line of the WHOLE difference (before it is paged) holds a private-key header or
    a full crypt hash, read in its complete format — a bare ``$1$`` (a regex replacement) is not
    one."""
    for x in lines:
        if x.startswith("@@"):
            continue
        text = x[1:] if x[:1] in ("+", "-", " ") else x
        if _PEM_PRIVATE.search(text) or _CRYPT_HASH.search(text):
            return True
    return False


def hunk(pf: PairFiles, path: str) -> Hunk:
    """The line difference of one path (a side with no file compared as empty), with its
    suppression reason when its text may not be given. Read once per path and reading."""
    if path not in pf.hunks:
        pf.hunks[path] = _hunk(pf, path)
    return pf.hunks[path]


def aligned_hunk(pf: PairFiles, af: AlignedFile) -> Hunk:
    """The line difference of a file subject: an ingested file paired by exact path reads exactly as
    the existing per-path ``hunk``; a no_ingester file, or a two-path (renamed / normalised)
    subject, reads each side at its own path, verifying the bytes against file_inventory's sha256.
    Read once per subject and reading, keyed by the subject's anchor key."""
    if not af.two_path and af.ingested and (af.path in pf.a.files or af.path in pf.b.files):
        return hunk(pf, af.path)
    key = af.path
    if key in pf.hunks:
        return pf.hunks[key]
    texts: list[list[str]] = []
    for side, p, sha in ((pf.a, af.path_a, af.sha_a), (pf.b, af.path_b, af.sha_b)):
        if p is None:
            texts.append([])
            continue
        lines, why = _read_file(side.root, p, sha)
        if lines is None:
            pf.hunks[key] = Hunk(None, unavailable=why)
            return pf.hunks[key]
        texts.append(lines)
    diff = list(difflib.unified_diff(texts[0], texts[1], n=HUNK_CONTEXT, lineterm=""))[2:]
    h = Hunk(diff, suppressed="embedded_secret") if _embedded_secret(diff) else Hunk(diff)
    pf.hunks[key] = h
    return h


def _hunk(pf: PairFiles, path: str) -> Hunk:
    ra, rb = pf.row("a", path), pf.row("b", path)
    texts: list[list[str]] = []
    for side, row in ((pf.a, ra), (pf.b, rb)):
        if row is None:
            texts.append([])
            continue
        lines, why = _read_file(side.root, path, row["sha256"])
        if lines is None:
            return Hunk(None, unavailable=why)
        texts.append(lines)
    diff = list(difflib.unified_diff(texts[0], texts[1], n=HUNK_CONTEXT, lineterm=""))[2:]
    kinds = {r["kind"] for r in (ra, rb) if r is not None}
    if "credential" in kinds:
        return Hunk(diff, suppressed="credential_material")
    if _sensitive(pf, path):
        return Hunk(diff, suppressed="sensitive_entry")
    if _embedded_secret(diff):
        return Hunk(diff, suppressed="embedded_secret")
    return Hunk(diff)


def _hunk_fields(h: Hunk) -> dict[str, Any]:
    """What a list page says of a hunk: its stats, or why it has none / why its text is held
    back."""
    if h.lines is None:
        return {"hunk_unavailable": h.unavailable}
    if h.suppressed is not None:
        stats = h.stats()
        del stats["bytes"]
        return {"hunk_suppressed": h.suppressed, "hunk_stats": stats}
    return {"hunk_stats": h.stats()}


def _encoded(text: str) -> int:
    """The bytes one string takes in the response's JSON encoding."""
    return len(json.dumps(text))


def _pieces(lines: list[str]) -> list[tuple[str, bool]]:
    """The hunk's lines, each cut into parts of at most HUNK_PIECE_BYTES encoded bytes: ``(text,
    continues)`` — ``continues`` when the next piece is the rest of the same line."""
    out: list[tuple[str, bool]] = []
    for line in lines:
        if _encoded(line) <= HUNK_PIECE_BYTES:
            out.append((line, False))
            continue
        part: list[str] = []
        size = 2
        for ch in line:
            cost = _encoded(ch) - 2
            if size + cost > HUNK_PIECE_BYTES:
                out.append(("".join(part), True))
                part, size = [], 2
            part.append(ch)
            size += cost
        out.append(("".join(part), False))
    return out


def hunk_page(h: Hunk, offset: int, page_bytes: int = HUNK_PAGE_BYTES) -> dict[str, Any]:
    """One page of a hunk's text from piece ``offset``: whole pieces within ``page_bytes`` (the
    encoded size of ``lines``; HUNK_PAGE_BYTES unless the page leaves less; always one piece),
    ``cut_at`` the pieces whose line continues in the next one."""
    assert h.lines is not None
    pieces = _pieces(h.lines)
    if offset < 0 or (offset > 0 and offset >= len(pieces)):
        raise FileDiffError(f"hunk_offset {offset} is past the hunk's {len(pieces)} pieces")
    page: list[str] = []
    cut: list[int] = []
    size = 0
    i = offset
    while i < len(pieces):
        text, continues = pieces[i]
        cost = _encoded(text) + 2  # the ", " between list items
        if page and size + cost > page_bytes:
            break
        page.append(text)
        if continues:
            cut.append(i)
        size += cost
        i += 1
    out: dict[str, Any] = {
        "lines": page,
        "hunk_offset": offset,
        "next_hunk_offset": i if i < len(pieces) else None,
        "total_pieces": len(pieces),
    }
    if cut:
        out["line_cut"] = True
        out["cut_at"] = cut
    return out


def shape_page(h: Hunk, offset: int, page_bytes: int = HUNK_PAGE_BYTES) -> dict[str, Any]:
    """One page of a suppressed hunk's shape from segment ``offset``: whole segments within
    ``page_bytes`` (the encoded size of ``segments``, as ``hunk_page``; always one segment)."""
    segments = h.shape()
    if offset < 0 or (offset > 0 and offset >= len(segments)):
        raise FileDiffError(f"hunk_offset {offset} is past the hunk's {len(segments)} segments")
    page: list[dict[str, Any]] = []
    size = 0
    i = offset
    while i < len(segments):
        cost = len(json.dumps(segments[i])) + 2
        if page and size + cost > page_bytes:
            break
        page.append(segments[i])
        size += cost
        i += 1
    return {
        "segments": page,
        "hunk_offset": offset,
        "next_hunk_offset": i if i < len(segments) else None,
        "total_segments": len(segments),
    }


# ── the reading ───────────────────────────────────────────────────────────────────────────


non_binary_anchor = dr.non_binary_anchor


def file_entry(pf: PairFiles, path: str, *, with_structure: bool = True) -> dict[str, Any]:
    """One path's entry without its hunk: identity, change, kind, the two sha256 values and — for a
    path that differs — its structured comparison."""
    ra, rb = pf.row("a", path), pf.row("b", path)
    change = change_of(ra, rb)
    out: dict[str, Any] = {"path": path, **_kind_fields(ra, rb), "change": change}
    out["sha_a"] = ra["sha256"] if ra is not None else None
    out["sha_b"] = rb["sha256"] if rb is not None else None
    if with_structure and change != "same":
        out["structured"] = structured(pf, path)
    return out


def subject_facts(entry: dict[str, Any]) -> dict[str, Any]:
    """What a judgement on one file rests on: its change, kind, both sha256 values and the counts of
    its structured comparison."""
    facts = {
        k: entry[k] for k in ("change", "kind", "kind_a", "kind_b", "sha_a", "sha_b") if k in entry
    }
    block = entry.get("structured")
    if isinstance(block, dict):
        facts["structured"] = structured_counts(block)
    return facts


def _af_ingested_exact(pf: PairFiles, af: AlignedFile) -> bool:
    """Whether this subject is an ingested file paired by exact path — the case that reads exactly
    as the pre-existing per-path machinery (identical entry, facts and hunk)."""
    return not af.two_path and af.ingested and (af.path in pf.a.files or af.path in pf.b.files)


def _entry_for(pf: PairFiles, af: AlignedFile) -> dict[str, Any]:
    """One subject's entry without its hunk. An ingested file paired by exact path keeps the
    per-path entry unchanged; a no_ingester file, or a two-path (renamed / normalised) subject,
    carries its status, both sha256, and (for two paths) each side's path and how they were
    paired."""
    if _af_ingested_exact(pf, af):
        return file_entry(pf, af.path)
    out: dict[str, Any] = {
        "path": af.path,
        "change": af.status,
        "sha_a": af.sha_a,
        "sha_b": af.sha_b,
    }
    if af.two_path:
        out["path_a"] = af.path_a
        out["path_b"] = af.path_b
        out["paired_by"] = af.paired_by
    return out


def _af_kinds(pf: PairFiles, af: AlignedFile) -> set[str]:
    out: set[str] = set()
    for side, p in (("a", af.path_a), ("b", af.path_b)):
        if p is not None:
            r = pf.row(side, p)
            if r is not None:
                out.add(str(r["kind"]))
    return out


def _listed_subjects(pf: PairFiles) -> list[AlignedFile]:
    """The file subjects a page can list / a path can read — every aligned subject except a
    normalised-``same`` file (not judged, no anchor), in display-path order."""
    return sorted(
        (
            af
            for af in aligned_files(pf)
            if not (af.status == "same" and af.paired_by == "path_normalized")
        ),
        key=lambda af: af.path,
    )


def _subject_index(pf: PairFiles) -> dict[str, AlignedFile]:
    """Resolve a ``path`` argument to its subject: by the anchor key (a single path, or
    ``{path_a}=>{path_b}``), or by either side's path for a two-path subject."""
    idx: dict[str, AlignedFile] = {}
    for af in _listed_subjects(pf):
        idx[af.path] = af
        if af.two_path:
            idx.setdefault(str(af.path_a), af)
            idx.setdefault(str(af.path_b), af)
    return idx


def file_subject_counts(pf: PairFiles) -> dict[str, int]:
    """The file subjects by status (the completion-denominator view): a normalised-``same`` file is
    not a subject, so not counted."""
    out = dict.fromkeys(STATUSES, 0)
    for af in _listed_subjects(pf):
        out[af.status] += 1
    return out


def _subject_facts_for(pf: PairFiles, af: AlignedFile) -> dict[str, Any]:
    """What a judgement on one file subject rests on. An ingested file paired by exact path keeps
    its existing facts unchanged (its kind, both sha256 and its structured-comparison counts); a
    no_ingester file, or a two-path (renamed / normalised) subject, rests on its status and both
    sha256 only."""
    if not af.two_path and af.ingested and (af.path in pf.a.files or af.path in pf.b.files):
        return subject_facts(file_entry(pf, af.path))
    return {"change": af.status, "sha_a": af.sha_a, "sha_b": af.sha_b}


def file_subjects(pf: PairFiles) -> dict[str, dr.Subject]:
    """anchor -> subject for every file subject of the pair: the non-ELF files of file_inventory,
    paired by exact path / normalised version dir / equal sha256. ``same`` files paired by exact
    path are kept (a judged file whose sides became equal reads as moved, not gone); a
    normalised-``same`` file (e.g. modules.builtin under a renamed version dir) is not judged and
    has no anchor."""
    facts: dict[str, dict[str, Any]] = {}
    for af in aligned_files(pf):
        if af.status == "same" and af.paired_by == "path_normalized":
            continue
        facts[af.path] = _subject_facts_for(pf, af)
    return dr.non_binary_subjects_of(facts, pf.run_a, pf.run_b)


def file_subject_items(pf: PairFiles, judged: dict[str, dr.DiffAnnotation]) -> list[dr.Item]:
    """Each CHANGED file subject as a completion-denominator item (bucket ``non_binary_file``),
    ordered after every diff's entries and the binary_presence binaries: unjudged until a judgement
    exists on its anchor. ``same`` files are not changed, so not counted; a .ko (an ELF information
    line) is not a file subject and never reaches here."""
    items: list[dr.Item] = []
    for af in aligned_files(pf):
        if af.status not in CHANGED_STATUSES:
            continue
        anchor = non_binary_anchor(pf.run_a, pf.run_b, af.path)
        j = judged.get(anchor)
        items.append(
            dr.Item(
                entry_id=anchor,
                anchor_ref=anchor,
                bucket="non_binary_file",
                subclass=af.status,
                tier=af.paired_by,
                state=dr.review_state(j),
                verdict=j.verdict if j is not None else None,
                order=(2, af.path),
            )
        )
    return items


def is_non_binary_anchor(anchor_ref: str) -> bool:
    """Whether an anchor names a non-binary file (its subject kind, the text between the first two
    ``#``, is ``non_binary``)."""
    parts = anchor_ref.split("#", 2)
    return len(parts) == 3 and parts[1] == "non_binary"


def file_review(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    *,
    source_stale: bool | None,
    source_stale_reason: str | None = None,
    pf: PairFiles | None = None,
) -> dict[str, dr.DiffAnnotation]:
    """Every judgement on a non-binary file of the run pair, read against the pair's files now —
    the file side's counterpart of patch_view.ViewReview, which never reads these. ``source_stale``
    is the caller's reading of the two runs (the MCP layer's stale-run gate): ``False`` only when
    both are servable; anything else reads ``needs_recheck``. A file judged whose path neither side
    records now is ``anchor_unresolved``; one whose facts moved is ``changed``."""
    rows = [
        r
        for r in dr.read_judgements(atlas, run_a, run_b)
        if (parts := dr.split_anchor(r["anchor_ref"], run_a, run_b)) is not None
        and parts[0] == "non_binary"
    ]
    if not rows:
        return {}
    subjects = file_subjects(pf if pf is not None else read_pair(atlas, run_a, run_b))
    staleness = {"source_stale": source_stale, "source_stale_reason": source_stale_reason}
    return {
        r["anchor_ref"]: dr.judge(
            r["anchor_ref"],
            r["verdict"],
            dr.stored_snapshot(r["basis_state"]),
            subjects.get(r["anchor_ref"]),
            withheld=False,
            staleness=staleness,
        )
        for r in rows
    }


def _fit_body(
    h: Hunk, offset: int, response: dict[str, Any], entry: dict[str, Any], budget: int | None
) -> None:
    """Put one page of ``h`` — its text (``hunk``), or its shape (``hunk_shape``) when it is
    suppressed — into ``entry``, which ``response`` holds: HUNK_PAGE_BYTES of it, or, when that
    takes ``response`` past ``budget``, only what the rest of the response leaves (always one piece
    or segment, so a response whose other parts alone are over the budget stays over it, and the
    caller marks it). The page ends where it ends; ``next_hunk_offset`` resumes from there, so the
    pages together hold the whole body once whatever each one's room was."""
    key, items, page_of = (
        ("hunk_shape", "segments", shape_page)
        if h.suppressed is not None
        else ("hunk", "lines", hunk_page)
    )
    page_bytes = HUNK_PAGE_BYTES
    while True:
        entry[key] = page = page_of(h, offset, page_bytes)
        if budget is None or len(page[items]) <= 1:
            return
        over = len(json.dumps(response)) - budget
        if over <= 0:
            return
        # The response grows with the page's list byte for byte (its encoded size is what
        # page_bytes bounds), so this room drops at least the overshoot: the next page is shorter.
        page_bytes = len(json.dumps(page[items])) - over


def file_diff(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    *,
    kind: str | None = None,
    change: str | None = None,
    path: str | None = None,
    offset: int = 0,
    limit: int = DEFAULT_LIMIT,
    hunk_offset: int = 0,
    detail: str = "full",
    review: dict[str, Any] | None = None,
    pf: PairFiles | None = None,
    ko_offset: int | None = None,
    budget: int | None = None,
) -> dict[str, Any]:
    """The run pair's non-binary files (see the module docstring). Without ``path``: a page of the
    files that differ (``change`` / ``kind`` filter; ``same`` only when asked for), each with its
    structured comparison and its hunk stats. With ``path``: that file in full — its structured
    lists paged by ``offset`` / ``limit`` (on the page with ``hunk_offset`` 0), its hunk text or
    suppressed shape paged by ``hunk_offset`` (on the page with ``offset`` 0). ``review`` maps an
    anchor to its review state (the caller's judgement read); a file with none reads the unjudged
    state, as an unjudged entry of a binary diff does. ``pf`` is the pair's files when the caller
    has read them already. ``ko_offset`` (alone: no ``path``, ``offset``, ``hunk_offset``,
    ``change``, ``kind`` or ``detail="summary"``) reads a page of the whole-pair lists — the .ko
    modules and the symbolic links — that the first page gives as counts. ``budget`` is the
    response's byte budget (None: none): with it, the line difference (or shape) on a file's own
    page takes only what the rest of that page leaves of it, at most HUNK_PAGE_BYTES — so a large
    structured item on the first page shortens the text there, and ``next_hunk_offset`` resumes it
    exactly. Raises FileDiffError on an argument or a side it cannot read."""
    if detail not in DETAILS:
        raise FileDiffError(f"detail must be one of {list(DETAILS)}; got {detail!r}")
    if change is not None and change not in STATUSES:
        raise FileDiffError(f"change must be one of {list(STATUSES)}; got {change!r}")
    if kind is not None and kind not in KINDS:
        raise FileDiffError(f"kind must be one of {list(KINDS)}; got {kind!r}")
    for name, value, low in (("offset", offset, 0), ("hunk_offset", hunk_offset, 0)):
        if isinstance(value, bool) or not isinstance(value, int) or value < low:
            raise FileDiffError(f"{name} must be an integer >= {low}; got {value!r}")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise FileDiffError(f"limit must be an integer in 1..{MAX_LIMIT}; got {limit!r}")
    if ko_offset is not None:
        if isinstance(ko_offset, bool) or not isinstance(ko_offset, int) or ko_offset < 0:
            raise FileDiffError(f"ko_offset must be an integer >= 0; got {ko_offset!r}")
        if path is not None or offset > 0 or hunk_offset > 0:
            raise FileDiffError(
                "ko_offset pages the whole-pair lists (.ko modules, symbolic links); offset pages "
                "the files and path / hunk_offset read one file: pass ko_offset alone"
            )
        if change is not None or kind is not None or detail != DETAILS[0]:
            raise FileDiffError(
                "ko_offset pages the whole-pair lists whole: change, kind and detail filter or "
                "shorten the file entries, not them — pass ko_offset alone"
            )
    if pf is None:
        pf = read_pair(atlas, run_a, run_b)
    review = review or {}
    pair = f"{run_a}::{run_b}"
    envelope: dict[str, Any] = {
        "run_pair": pair,
        "run_a": run_a,
        "run_b": run_b,
        "detail": detail,
        **counts_by_kind(pf),
        "file_subject_counts": file_subject_counts(pf),
        "legend": LEGEND,
        "caveats": CAVEATS,
    }

    def decorate(af: AlignedFile, entry: dict[str, Any], *, full: bool) -> dict[str, Any]:
        anchor = non_binary_anchor(run_a, run_b, af.path)
        out = dict(entry)
        block = out.pop("structured", None)
        if block is not None:
            if detail == "summary":
                out["structured_counts"] = structured_counts(block)
                out.update(
                    {
                        k: block[k]
                        for k in ("structured_available", "recorded_rows_same")
                        if k in block
                    }
                )
            else:
                out["structured"] = block if full else _cut_lists(block, LIST_PAGE_ITEMS)
        if entry["change"] != "same":
            out.update(_hunk_fields(aligned_hunk(pf, af)))
        out["paired_by"] = af.paired_by
        out["anchor_ref"] = anchor
        out["review_state"] = review.get(anchor, dr.STATES[0])
        return out

    if ko_offset is not None:
        return {**envelope, **whole_pair_page(pf, ko_offset, limit)}

    if path is not None:
        af = _subject_index(pf).get(path)
        if af is None:
            raise FileDiffError(f"no file with path {path!r} is recorded on either side of {pair}")
        if offset > 0 and hunk_offset > 0:
            raise FileDiffError(
                "offset pages a file's structured lists and hunk_offset its line difference: "
                "pass one of them above 0, not both"
            )
        entry = decorate(af, _entry_for(pf, af), full=True)
        if detail == "full":
            block = entry.pop("structured", None)
            if block is not None:
                if hunk_offset == 0:
                    entry["structured"] = structured_page(block, offset, limit)
                else:
                    entry["structured_on_page"] = "hunk_offset=0"
            if entry["change"] != "same":
                h = aligned_hunk(pf, af)
                if h.lines is not None and offset > 0:
                    entry["hunk_on_page"] = "offset=0"
                elif h.lines is not None:
                    _fit_body(h, hunk_offset, {**envelope, "entry": entry}, entry, budget)
        return {**envelope, "entry": entry}

    wanted = (change,) if change is not None else CHANGED_STATUSES
    chosen = [
        af
        for af in _listed_subjects(pf)
        if af.status in wanted and (kind is None or kind in _af_kinds(pf, af))
    ]
    page = chosen[offset : offset + limit]
    entries = [decorate(af, _entry_for(pf, af), full=False) for af in page]
    end = offset + len(page)
    result = {
        **envelope,
        "filters": {"kind": kind, "change": change},
        "entries": entries,
        "total_entries": len(chosen),
        "next_offset": end if end < len(chosen) else None,
        "truncated_by_bytes": False,
        "read_one_with": f'get_file_diff(run_pair={json.dumps(pair)}, path="<path>")',
    }
    if offset == 0:  # whole-pair information lines, given once with the first page
        from treasure_map.lib.query.ko_changes import ko_counts

        result["ko_changes"] = ko_counts(pf)
        result["symlink_changes"] = symlink_first_page(pf)
    return result


def file_summary(atlas: sqlite3.Connection, run_a: str, run_b: str) -> dict[str, Any]:
    """The run pair's file counts and the call that lists them, or why they cannot be read — the
    block a binary diff's meta and review start carry."""
    pair = f"{run_a}::{run_b}"
    try:
        pf = read_pair(atlas, run_a, run_b)
    except FileDiffError as exc:
        return {"unavailable": str(exc)}
    counts = counts_by_kind(pf)
    return {
        "counts": counts["counts"],
        "counts_by_kind": counts["counts_by_kind"],
        "file_subject_counts": file_subject_counts(pf),
        "next": f"get_file_diff(run_pair={json.dumps(pair)})",
    }
