# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Binaries held by one run of a pair only: subjects no diff can cover, because the other run
holds nothing to compare them with.

A candidate-holding binary that no diff of a run pair covers is a blind spot
(lib/query/diff_align.not_diffed_binaries, reason ``binary_not_diffed``) — UNLESS the other run
provably has no counterpart for it. Then it is listed here instead, as a subject of its own
(``a_only`` for a binary of run A, ``b_only`` for one of run B), with its candidates, the recorded
references to it, and a review state. Provably means: the other run's analysis.db was read and
holds

  * no binary of the same content hash, of the same name, or at the same path under the firmware
    root (``current_binaries``),
  * no non-binary file at that path (``non_binary_files``),
  * no symlink at that path (``fs_symlinks``).

Paths are compared under each run's firmware root: a binary's recorded path is absolute (it
carries the run's unpack directory), the other two tables record paths relative to the root. A
binary whose path cannot be made relative, a run with no recorded firmware root, an analysis.db
that cannot be read or lacks one of the tables — each keeps the binary a blind spot.

``referenced_by`` lists the recorded references to the binary in its own run: a script call whose
command's basename is the binary's name, a web endpoint whose path's last segment is (exact
equality, never a substring), each with the state of the same reference on the other run. Only
the recorded tables are read, never a firmware file, so an empty list is not proof the binary is
unreferenced.

A judgement on one of these is a diff-side judgement (lib/overlay.py writes it) anchored
``{run_a}::{run_b}#binary_presence#{a_only|b_only}:{rel_path}`` and scoped to the run pair, like a
non-binary file's (lib/query/file_diff). READ-ONLY: nothing here writes.
"""

from __future__ import annotations

import posixpath
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query.diff_align import NotDiffedBinary, not_diffed_groups
from treasure_map.lib.ro_db import ro_connect

SIDES = {"a": "a_only", "b": "b_only"}
BASIS = "not in the other side's binary inventory, non-binary files or symlinks"
REFERENCED_BY_NOTE = (
    "recorded references only (script_calls, web_endpoints); no recorded reference is not proof "
    "the binary is unreferenced"
)
# The state of a reference on the other run, read from that run's recorded tables.
PRESENT = "present"  # the same file there records it too, or holds the same content
NOT_RECORDED = "not_recorded"  # the same file is there, and its records hold no such reference
FILE_ABSENT = "file_absent"  # the other run has no file at that path
UNDETERMINED = "undetermined"  # the other run cannot be read, or records nothing of that file
_REQUIRED_TABLES = ("current_binaries", "non_binary_files", "fs_symlinks")


@dataclass(frozen=True)
class PresentBinary:
    """One binary held by one run of the pair only."""

    side: str  # "a" or "b"
    run: str
    name: str
    rel_path: str
    path: str  # as the run recorded it (absolute)
    sha256: str | None
    candidates: int
    by_class: dict[str, int]
    referenced_by: list[dict[str, Any]]

    @property
    def tag(self) -> str:
        return SIDES[self.side]


@dataclass
class Presence:
    """The binaries of one run pair held by one run only, and the (side, path) of each — which
    diff_align.not_diffed_binaries takes out of its blind spots."""

    run_a: str
    run_b: str
    items: list[PresentBinary] = field(default_factory=list)

    @property
    def excluded(self) -> frozenset[tuple[str, str | None]]:
        return frozenset((b.side, b.path) for b in self.items)

    def anchor(self, b: PresentBinary) -> str:
        return dr.binary_presence_anchor(self.run_a, self.run_b, b.tag, b.rel_path)


# ── one run's analysis.db, as far as this reads it ───────────────────────────────────────────


@dataclass
class _RunDb:
    """One run's firmware root and the recorded tables this module reads; ``error`` says why
    they could not be read (None when they were)."""

    root: str | None
    error: str | None = None
    binaries: list[tuple[str | None, str | None, str | None]] = field(default_factory=list)
    files: dict[str, str | None] = field(default_factory=dict)  # rel path -> sha256
    symlinks: set[str] = field(default_factory=set)
    # rel path of a file -> the script-call commands / web-endpoint paths recorded in it
    script_calls: dict[str, list[tuple[str, int | None]]] = field(default_factory=dict)
    web_endpoints: dict[str, list[str]] = field(default_factory=dict)
    file_ids: dict[int, str] = field(default_factory=dict)


def _read_run(atlas: sqlite3.Connection, run_id: str) -> _RunDb:
    row = atlas.execute(
        "SELECT firmware_path, analysis_db_path FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    if row is None:
        return _RunDb(None, "run_unknown")
    root, db_path = row[0], row[1]
    out = _RunDb(str(root).rstrip("/") if root else None)
    if not root:
        out.error = "firmware_path_unrecorded"
    if not db_path:
        out.error = out.error or "analysis_db_unrecorded"
        return out
    try:
        conn = ro_connect(db_path)
    except sqlite3.Error:
        out.error = out.error or "analysis_db_unreadable"
        return out
    try:
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")
        }
        missing = [t for t in _REQUIRED_TABLES if t not in tables]
        if missing:
            out.error = out.error or f"missing_table:{missing[0]}"
            return out
        out.binaries = [
            (n, p, s) for n, p, s in conn.execute("SELECT name, path, sha256 FROM current_binaries")
        ]
        for fid, path, sha in conn.execute("SELECT id, path, sha256 FROM non_binary_files"):
            if path:
                out.files[str(path)] = sha
                out.file_ids[int(fid)] = str(path)
        out.symlinks = {
            str(p) for (p,) in conn.execute("SELECT link_path FROM fs_symlinks") if p is not None
        }
        if "script_calls" in tables:
            for fid, command, line in conn.execute(
                "SELECT file_id, command, line_number FROM script_calls"
            ):
                path = out.file_ids.get(fid)
                if path is not None and command:
                    out.script_calls.setdefault(path, []).append((str(command), line))
        if "web_endpoints" in tables:
            for fid, wpath in conn.execute("SELECT file_id, path FROM web_endpoints"):
                path = out.file_ids.get(fid)
                if path is not None and wpath:
                    out.web_endpoints.setdefault(path, []).append(str(wpath))
    except sqlite3.Error:
        out.error = out.error or "analysis_db_unreadable"
    finally:
        conn.close()
    return out


def rel_path(root: str | None, path: str | None) -> str | None:
    """``path`` under the firmware ``root`` (no leading slash), or None when it is not under it."""
    if not root or not path:
        return None
    prefix = root.rstrip("/") + "/"
    if not path.startswith(prefix):
        return None
    rel = path[len(prefix) :].lstrip("/")
    return rel or None


def _endpoint_name(path: str) -> str:
    """The last segment of a web endpoint's path, its query and fragment left off."""
    bare = path.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    return bare.rsplit("/", 1)[-1]


def _command_name(command: str) -> str:
    return posixpath.basename(command.strip())


def _has_counterpart(other: _RunDb, name: str, rel: str, sha: str | None) -> bool:
    """Whether the other run holds anything this binary could be a counterpart of: a binary with
    its content, its name or its path, a non-binary file at its path, or a symlink at its path."""
    for o_name, o_path, o_sha in other.binaries:
        if sha is not None and o_sha == sha:
            return True
        if o_name == name:
            return True
        if rel_path(other.root, o_path) == rel:
            return True
    return rel in other.files or rel in other.symlinks


# ── references ───────────────────────────────────────────────────────────────────────────────


def _other_state(own: _RunDb, other: _RunDb, path: str, kind: str, name: str) -> str:
    """The state, on the other run, of the reference ``kind`` to ``name`` recorded in the file at
    ``path``."""
    if other.error is not None:
        return UNDETERMINED
    if path not in other.files:
        return FILE_ABSENT
    if own.files.get(path) is not None and other.files[path] == own.files.get(path):
        return PRESENT
    if kind == "script_call":
        records = [_command_name(c) for c, _line in other.script_calls.get(path, [])]
    else:
        records = [_endpoint_name(w) for w in other.web_endpoints.get(path, [])]
    if name in records:
        return PRESENT
    return NOT_RECORDED if records else UNDETERMINED


def _referenced_by(own: _RunDb, other: _RunDb, name: str) -> list[dict[str, Any]]:
    """The recorded references to ``name`` in its own run, each with its state on the other run.
    Ordered by file path, then kind, then line."""
    out: list[dict[str, Any]] = []
    for path, calls in own.script_calls.items():
        for command, line in calls:
            if _command_name(command) == name:
                out.append(
                    {
                        "path": path,
                        "kind": "script_call",
                        "line_number": line,
                        "other_side": _other_state(own, other, path, "script_call", name),
                    }
                )
    for path, endpoints in own.web_endpoints.items():
        for endpoint in endpoints:
            if _endpoint_name(endpoint) == name:
                out.append(
                    {
                        "path": path,
                        "kind": "web_endpoint",
                        "other_side": _other_state(own, other, path, "web_endpoint", name),
                    }
                )
    out.sort(key=lambda r: (r["path"], r["kind"], r.get("line_number") or 0))
    return out


# ── the binaries ─────────────────────────────────────────────────────────────────────────────


def find_presence(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    groups: dict[str, dict[str, dict[str | None, NotDiffedBinary]]] | None = None,
) -> Presence:
    """The binaries of the pair held by one run only. ``groups`` is diff_align.not_diffed_groups'
    result when the caller holds it. Only ``binary_not_diffed`` binaries are candidates: a binary
    shadowed by a same-named diffed one, or identical on both sides, has a counterpart by
    definition."""
    if groups is None:
        groups = not_diffed_groups(atlas, run_a, run_b)
    out = Presence(run_a, run_b)
    wanted = {side: groups.get(side, {}).get("binary_not_diffed", {}) for side in ("a", "b")}
    if not wanted["a"] and not wanted["b"]:
        return out
    runs = {"a": _read_run(atlas, run_a), "b": _read_run(atlas, run_b)}
    for side, other_side in (("a", "b"), ("b", "a")):
        own, other = runs[side], runs[other_side]
        if other.error is not None or other.root is None:
            continue  # nothing can be proven absent from a run that was not read
        if own.error is not None or own.root is None:
            continue  # its path cannot be placed under the root, nor its references read
        for path, b in sorted(wanted[side].items(), key=lambda kv: kv[0] or ""):
            rel = rel_path(own.root, path)
            if path is None or rel is None:
                continue
            name = posixpath.basename(path)
            sha = b.sha
            for o_name, o_path, o_sha in own.binaries:
                if o_path == path:
                    name = o_name or name
                    sha = sha or o_sha
                    break
            if _has_counterpart(other, name, rel, sha):
                continue
            out.items.append(
                PresentBinary(
                    side=side,
                    run=run_a if side == "a" else run_b,
                    name=name,
                    rel_path=rel,
                    path=path,
                    sha256=sha,
                    candidates=len(b.refs),
                    by_class={k: len(v) for k, v in sorted(b.by_class.items())},
                    referenced_by=_referenced_by(own, other, name),
                )
            )
    return out


def subject_facts(b: PresentBinary) -> dict[str, Any]:
    """What a judgement on one of these rests on; any change re-checks it."""
    return {
        "side": b.tag,
        "rel_path": b.rel_path,
        "name": b.name,
        "sha256": b.sha256,
        "candidates": b.candidates,
        "candidates_by_sink_class": dict(b.by_class),
        "referenced_by": [dict(r) for r in b.referenced_by],
    }


def presence_subjects(presence: Presence) -> dict[str, dr.Subject]:
    """anchor -> subject, for every binary of the pair held by one run only."""
    return dr.binary_presence_subjects_of(
        {(b.tag, b.rel_path): subject_facts(b) for b in presence.items},
        presence.run_a,
        presence.run_b,
    )


def presence_review(
    atlas: sqlite3.Connection,
    presence: Presence,
    *,
    source_stale: bool | None,
    source_stale_reason: str | None,
) -> dict[str, dr.DiffAnnotation]:
    """Every judgement on a binary_presence anchor of the pair, read against the binaries as they
    are now (a gone binary reads anchor_unresolved). ``source_stale`` is the caller's reading of
    the two runs — stale when either is; unknown (None) reads needs_recheck."""
    subjects = presence_subjects(presence)
    staleness = {"source_stale": source_stale, "source_stale_reason": source_stale_reason}
    out: dict[str, dr.DiffAnnotation] = {}
    for row in dr.read_judgements(atlas, presence.run_a, presence.run_b):
        anchor = row["anchor_ref"]
        if not dr.is_binary_presence_anchor(anchor):
            continue
        out[anchor] = dr.judge(
            anchor,
            row["verdict"],
            dr.stored_snapshot(row["basis_state"]),
            subjects.get(anchor),
            withheld=False,
            staleness=staleness,
        )
    return out


def presence_items(presence: Presence, judged: dict[str, dr.DiffAnnotation]) -> list[dr.Item]:
    """Each binary as a progress item (bucket ``binary_presence``), ordered after every diff's
    entries: unjudged until a judgement exists on its anchor."""
    items: list[dr.Item] = []
    for b in presence.items:
        anchor = presence.anchor(b)
        j = judged.get(anchor)
        items.append(
            dr.Item(
                entry_id=anchor,
                anchor_ref=anchor,
                bucket="binary_presence",
                subclass=b.tag,
                tier=b.candidates,
                state=dr.review_state(j),
                verdict=j.verdict if j is not None else None,
                order=(1, b.tag, b.rel_path),
            )
        )
    return items


def presence_block(presence: Presence, judged: dict[str, dr.DiffAnnotation]) -> dict[str, Any]:
    """The ``binary_presence`` block: each binary with its anchor and review state, per side."""
    out: dict[str, Any] = {"a_only": [], "b_only": []}
    for b in presence.items:
        anchor = presence.anchor(b)
        out[b.tag].append(
            {
                "name": b.name,
                "rel_path": b.rel_path,
                "sha256": b.sha256,
                "candidates": b.candidates,
                "candidates_by_sink_class": dict(b.by_class),
                "anchor_ref": anchor,
                "review_state": dr.review_state(judged.get(anchor)),
                "referenced_by": [dict(r) for r in b.referenced_by],
                "referenced_by_note": REFERENCED_BY_NOTE,
            }
        )
    out["basis"] = BASIS
    out["see"] = "list_candidates(run_id=<run of that side>, binary=<name>)"
    out["annotate_with"] = (
        "annotate_diff(anchor_ref=<anchor_ref>, run_pair="
        f'"{dr.run_pair(presence.run_a, presence.run_b)}", verdict=..., rationale=...)'
    )
    return out


def presence_counts(presence: Presence, judged: dict[str, dr.DiffAnnotation]) -> dict[str, Any]:
    """Per side: how many binaries, their candidates, and how many have no judgement yet."""
    out: dict[str, Any] = {}
    for side, tag in SIDES.items():
        mine = [b for b in presence.items if b.side == side]
        out[tag] = {
            "binaries": len(mine),
            "candidates": sum(b.candidates for b in mine),
            "not_looked_at": sum(1 for b in mine if presence.anchor(b) not in judged),
        }
    return out


# ── a judgement on one: what its `checked` may cite ──────────────────────────────────────────


def require_presence_checked(
    atlas: sqlite3.Connection,
    presence: Presence,
    anchor_ref: str,
    items: list[str],
    field: str,
) -> None:
    """The ``checked`` / ``evidence`` rule on a binary_presence judgement: an item resolves when it
    is the judged binary's own anchor, or an evidence_ref of one of that binary's candidates in its
    own run. An item that looks like an anchor or an evidence_ref but is neither — another
    binary's candidate, another run's — is refused by name; plain text is kept but does not count;
    at least one item must resolve."""
    from treasure_map.lib.query.diff_annotations import _anchor_marker

    target = next((b for b in presence.items if presence.anchor(b) == anchor_ref), None)
    if target is None:  # the caller resolved the anchor already
        raise ConfigError(f"{anchor_ref!r} names no binary held by one run of the pair only")
    hits = 0
    for i, raw in enumerate(items):
        item = raw.strip()
        if item == anchor_ref:
            hits += 1
            continue
        if item.startswith(f"{target.run}#"):
            found = atlas.execute(
                "SELECT 1 FROM instance WHERE source_run_id = ? AND evidence_ref = ? "
                "AND (binary_content_hash = ? OR binary_path = ?) LIMIT 1",
                (target.run, item, target.sha256, target.path),
            ).fetchone()
            if found is not None:
                hits += 1
                continue
            raise ConfigError(
                f"{field}[{i}] is not a candidate of {target.name} ({target.rel_path}) in run "
                f"{target.run!r}"
            )
        if dr.is_binary_presence_anchor(item) or _anchor_marker(item) is not None:
            raise ConfigError(
                f"{field}[{i}] looks like an anchor but is neither this binary's anchor_ref nor "
                f"one of its candidates' evidence_ref in run {target.run!r}"
            )
    if hits == 0:
        raise ConfigError(
            f"{field} needs at least one item that resolves: this binary's own anchor_ref, or an "
            f"evidence_ref of one of its candidates in run {target.run!r} (list_candidates); "
            "plain-text notes are kept but do not count"
        )
