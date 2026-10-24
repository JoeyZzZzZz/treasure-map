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
# response.
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
        "binary_content (a NUL byte), no_scan_hash (a side recorded no sha256)"
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


_SUB_TABLES = {
    "script_calls": "file_id, command, raw_line, line_number",
    "config_entries": "file_id, section, key, value, is_sensitive",
    "credentials": "file_id, cred_type, identifier, algorithm, material, is_sensitive",
    "web_endpoints": "file_id, asset_type, method, path, source",
    "web_form_fields": "file_id, field_keyword",
}


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
        for table, cols in _SUB_TABLES.items():
            by_file: dict[int, list[dict[str, Any]]] = {}
            for r in conn.execute(f"SELECT {cols} FROM {table} ORDER BY id"):  # noqa: S608
                by_file.setdefault(r["file_id"], []).append(dict(r))
            rows[table] = by_file
    except sqlite3.Error as exc:
        raise FileDiffError(
            f"run {run_id!r}: its non-binary records cannot be read ({exc})"
        ) from exc
    finally:
        conn.close()
    return _Side(run_id, run.firmware_path, files, null_path, duplicate_path, rows)


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


def _script_block(rows_a: list[dict[str, Any]], rows_b: list[dict[str, Any]]) -> dict[str, Any]:
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


def _read_file(root: str | None, path: str, sha: str | None) -> tuple[list[str] | None, str | None]:
    """``(lines, None)`` of one side's file under its firmware root, or ``(None, why)``."""
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
        with open(real, "rb") as fh:
            data = fh.read()
    except OSError:
        return None, "file_unreadable"
    if hashlib.sha256(data).hexdigest() != sha.lower():
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


def hunk_page(h: Hunk, offset: int) -> dict[str, Any]:
    """One page of a hunk's text from piece ``offset``: whole pieces within HUNK_PAGE_BYTES (always
    one), ``cut_at`` the pieces whose line continues in the next one."""
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
        if page and size + cost > HUNK_PAGE_BYTES:
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


def shape_page(h: Hunk, offset: int) -> dict[str, Any]:
    """One page of a suppressed hunk's shape from segment ``offset``, within HUNK_PAGE_BYTES."""
    segments = h.shape()
    if offset < 0 or (offset > 0 and offset >= len(segments)):
        raise FileDiffError(f"hunk_offset {offset} is past the hunk's {len(segments)} segments")
    page: list[dict[str, Any]] = []
    size = 0
    i = offset
    while i < len(segments):
        cost = len(json.dumps(segments[i])) + 2
        if page and size + cost > HUNK_PAGE_BYTES:
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


def file_subjects(pf: PairFiles) -> dict[str, dr.Subject]:
    """anchor -> subject for every aligned path of the pair (``same`` included)."""
    facts = {p: subject_facts(file_entry(pf, p)) for p in pf.paths}
    return dr.non_binary_subjects_of(facts, pf.run_a, pf.run_b)


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
) -> dict[str, Any]:
    """The run pair's non-binary files (see the module docstring). Without ``path``: a page of the
    files that differ (``change`` / ``kind`` filter; ``same`` only when asked for), each with its
    structured comparison and its hunk stats. With ``path``: that file in full — its structured
    lists paged by ``offset`` / ``limit`` (on the page with ``hunk_offset`` 0), its hunk text or
    suppressed shape paged by ``hunk_offset`` (on the page with ``offset`` 0). ``review`` maps an
    anchor to its review state (the caller's judgement read); a file with none reads the unjudged
    state, as an unjudged entry of a binary diff does. ``pf`` is the pair's files when the caller
    has read them already. Raises FileDiffError on an argument or a side it cannot read."""
    if detail not in DETAILS:
        raise FileDiffError(f"detail must be one of {list(DETAILS)}; got {detail!r}")
    if change is not None and change not in CHANGES:
        raise FileDiffError(f"change must be one of {list(CHANGES)}; got {change!r}")
    if kind is not None and kind not in KINDS:
        raise FileDiffError(f"kind must be one of {list(KINDS)}; got {kind!r}")
    for name, value, low in (("offset", offset, 0), ("hunk_offset", hunk_offset, 0)):
        if isinstance(value, bool) or not isinstance(value, int) or value < low:
            raise FileDiffError(f"{name} must be an integer >= {low}; got {value!r}")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise FileDiffError(f"limit must be an integer in 1..{MAX_LIMIT}; got {limit!r}")
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
        "legend": LEGEND,
        "caveats": CAVEATS,
    }

    def decorate(entry: dict[str, Any], *, full: bool) -> dict[str, Any]:
        anchor = non_binary_anchor(run_a, run_b, entry["path"])
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
            out.update(_hunk_fields(hunk(pf, entry["path"])))
        out["anchor_ref"] = anchor
        out["review_state"] = review.get(anchor, dr.STATES[0])
        return out

    if path is not None:
        if path not in pf.a.files and path not in pf.b.files:
            raise FileDiffError(f"no file with path {path!r} is recorded on either side of {pair}")
        if offset > 0 and hunk_offset > 0:
            raise FileDiffError(
                "offset pages a file's structured lists and hunk_offset its line difference: "
                "pass one of them above 0, not both"
            )
        entry = decorate(file_entry(pf, path), full=True)
        if detail == "full":
            block = entry.pop("structured", None)
            if block is not None:
                if hunk_offset == 0:
                    entry["structured"] = structured_page(block, offset, limit)
                else:
                    entry["structured_on_page"] = "hunk_offset=0"
            if entry["change"] != "same":
                h = hunk(pf, path)
                if h.lines is not None and offset > 0:
                    entry["hunk_on_page"] = "offset=0"
                elif h.lines is not None and h.suppressed is not None:
                    entry["hunk_shape"] = shape_page(h, hunk_offset)
                elif h.lines is not None:
                    entry["hunk"] = hunk_page(h, hunk_offset)
        return {**envelope, "entry": entry}

    wanted = (change,) if change is not None else LISTED_CHANGES
    chosen = []
    for p in pf.paths:
        ra, rb = pf.row("a", p), pf.row("b", p)
        if change_of(ra, rb) not in wanted:
            continue
        if kind is not None and kind not in {r["kind"] for r in (ra, rb) if r is not None}:
            continue
        chosen.append(p)
    page = chosen[offset : offset + limit]
    entries = [decorate(file_entry(pf, p), full=False) for p in page]
    end = offset + len(page)
    return {
        **envelope,
        "filters": {"kind": kind, "change": change},
        "entries": entries,
        "total_entries": len(chosen),
        "next_offset": end if end < len(chosen) else None,
        "truncated_by_bytes": False,
        "read_one_with": f'get_file_diff(run_pair={json.dumps(pair)}, path="<path>")',
    }


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
        "next": f"get_file_diff(run_pair={json.dumps(pair)})",
    }
