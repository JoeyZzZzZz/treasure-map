# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Overlay: a mutable annotation layer laid over the read-only candidate map.

An overlay row holds an AGENT's OWN annotation about one scan/hunt candidate — never a tool-emitted
fact, and NEVER written back onto the instance/pattern tables (which stay untouched, so the base map
is unchanged whether the overlay is empty or full). A consumer reads the base map, decides something
about a candidate, and records that decision here, keyed by the candidate's ``evidence_ref``.

Two things keep the layer honest:

  * SEPARATION — the write path touches ONLY the ``overlay`` table. It READS ``instance`` rows to
    snapshot the facts an annotation rested on, but never mutates them. (This is also why the layer
    lives here and not under the append-only atlas writer: an annotation is mutable — one row per
    anchor, last write wins — and ``clear_overlay`` is a full-table delete, neither of which the
    append-and-corroborate store permits.)

  * STALENESS — each annotation snapshots the candidate's BASIS at write time: the function's
    pseudocode hash plus the per-sibling dimension set (an ``evidence_ref`` can map to several
    instances, one per pattern, so the snapshot is a SET keyed by pattern_id, not a single row). A
    later read re-derives that basis and REPORTS what moved — the pseudocode text changed, or which
    dimensions of which sibling changed — so an annotation standing on now-stale facts is flagged
    for re-review instead of silently trusted. The layer reports those facts ONLY; whether a changed
    basis undoes the annotation is the consumer's judgement, never asserted here.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from treasure_map.lib.errors import ConfigError

# The agent verdicts an annotation may carry. This layer stores a CONCLUSION, not a task: an
# annotation says what was decided about a candidate, and ``inconclusive`` is itself a conclusion —
# it was looked at, and nothing decisive could be established within what this tool can see (the
# rationale carries the next step). A verdict that sits at bias 0 leaves the base-map position
# alone; the two opt-in view biases (+1 float, -1 sink) are exposed as a FACT for a view layer to
# consume — the base map's own ordering is never touched by this module.
#
# The vocabulary can change freely now that no database constraint pins it, so anything reading a
# verdict must tolerate one it does not know: an older database can still hold a retired word.
_VERDICTS = ("inconclusive", "suspicious", "excluded", "safe")
_VERDICT_BIAS = {
    "inconclusive": 0,
    "suspicious": 1,
    "excluded": -1,
    "safe": -1,
}
# Coarse attribution only. NULL means "not recorded"; a fabricated identity is never written (the
# schema CHECK enforces this set). A real identity matters only at a later promotion boundary.
_ATTRIBUTION = ("agent", "agent-via-mcp")

# The base-map dimensions an annotation rests on. Snapshotted per sibling instance so a later read
# can report which fact moved under a standing annotation. pattern_id keys the sibling: it is
# content-stable across a re-scan (patterns are content-deduped on upsert and never deleted), which
# is what makes a same-content re-scan produce ZERO basis delta.
_BASIS_DIMS = (
    "reachability_status",
    "blocking_mechanism",
    "exposure_shape",
    "flow_evidence",
    "provenance_level",
    "scope_origin",
    "origin",
)


@dataclass(frozen=True)
class Basis:
    """The facts one annotation rested on, snapshotted at write time.

    ``resolved`` is False when the ref matched no instance (a dangling anchor). ``pseudocode_known``
    is False when no pseudocode hash was recorded on either side — then a text change CANNOT be
    seen, so the read reports 'unverifiable', never a false 'unchanged'. ``siblings`` is the
    ref-level SET of ``(pattern_id, *dimensions)`` — a SET, so a change to ANY sibling is caught.
    """

    resolved: bool
    pseudocode_hash: str | None
    pseudocode_known: bool
    siblings: frozenset[tuple[Any, ...]]

    def to_json(self) -> str:
        return json.dumps(
            {
                "resolved": self.resolved,
                "pseudocode_hash": self.pseudocode_hash,
                "pseudocode_known": self.pseudocode_known,
                # sorted for a deterministic snapshot (a set has no order); json.dumps keys it
                "siblings": sorted((list(s) for s in self.siblings), key=json.dumps),
            }
        )

    @classmethod
    def from_json(cls, raw: str | None) -> Basis | None:
        if not raw:
            return None
        d = json.loads(raw)
        return cls(
            resolved=bool(d.get("resolved")),
            pseudocode_hash=d.get("pseudocode_hash"),
            pseudocode_known=bool(d.get("pseudocode_known")),
            siblings=frozenset(tuple(s) for s in d.get("siblings", [])),
        )


def capture_basis(atlas: sqlite3.Connection, evidence_ref: str) -> Basis:
    """Snapshot the base-map facts one ``evidence_ref`` rests on: the function's pseudocode hash
    (function-level, shared across siblings — first non-null wins) plus the ref-level SET of
    per-sibling ``(pattern_id, *dimensions)``. A pure READ of ``instance`` (never a write)."""
    rows = atlas.execute(
        "SELECT pattern_id, pseudocode_hash, "  # noqa: S608 -- _BASIS_DIMS is a fixed literal tuple
        + ", ".join(_BASIS_DIMS)
        + " FROM instance WHERE evidence_ref = ? ORDER BY pattern_id",
        (evidence_ref,),
    ).fetchall()
    if not rows:
        return Basis(
            resolved=False, pseudocode_hash=None, pseudocode_known=False, siblings=frozenset()
        )
    ph = next((r["pseudocode_hash"] for r in rows if r["pseudocode_hash"]), None)
    siblings = frozenset((r["pattern_id"], *(r[d] for d in _BASIS_DIMS)) for r in rows)
    return Basis(
        resolved=True, pseudocode_hash=ph, pseudocode_known=ph is not None, siblings=siblings
    )


def _dim_delta(old: frozenset[tuple[Any, ...]], new: frozenset[tuple[Any, ...]]) -> dict[str, Any]:
    """Set-level diff of two per-sibling dimension sets. ``changed`` is decided by SET equality
    (robust — catches any moved dimension, an added or dropped sibling), so it never degrades to a
    single-row check; the per-pattern detail is a best-effort human hint on top."""
    if old == new:
        return {"changed": False, "added": [], "removed": [], "moves": []}
    old_by = {t[0]: t[1:] for t in old}
    new_by = {t[0]: t[1:] for t in new}
    added = sorted(p for p in new_by if p not in old_by)
    removed = sorted(p for p in old_by if p not in new_by)
    moves = []
    for pid in sorted(set(old_by) & set(new_by)):
        if old_by[pid] != new_by[pid]:
            moved = {
                _BASIS_DIMS[i]: [old_by[pid][i], new_by[pid][i]]
                for i in range(len(_BASIS_DIMS))
                if old_by[pid][i] != new_by[pid][i]
            }
            moves.append({"pattern_id": pid, "moved": moved})
    return {"changed": True, "added": added, "removed": removed, "moves": moves}


def basis_delta(
    atlas: sqlite3.Connection, evidence_ref: str, stored: Basis | None
) -> dict[str, Any]:
    """Re-derive the basis and REPORT what moved since the annotation was written — facts only,
    never a judgement that it is now wrong. ``state`` is one of: ``anchor_unresolved`` (the ref
    no longer resolves), ``changed`` (pseudocode text or a dimension moved), ``unverifiable`` (no
    pseudocode hash to compare, so a text change cannot be told — an honest can't-say, not a clean
    bill), or ``unchanged``."""
    if stored is None:
        return {
            "state": "unverifiable",
            "pseudocode": "unverifiable",
            "dimensions": _dim_delta(frozenset(), frozenset()),
        }
    cur = capture_basis(atlas, evidence_ref)
    if not cur.resolved:
        return {
            "state": "anchor_unresolved",
            "pseudocode": "unverifiable",
            "dimensions": _dim_delta(stored.siblings, frozenset()),
        }
    if not stored.pseudocode_known or not cur.pseudocode_known:
        pc = "unverifiable"  # NULL-honest: no hash on one side -> a text change cannot be seen
    elif stored.pseudocode_hash != cur.pseudocode_hash:
        pc = "changed"
    else:
        pc = "unchanged"
    dims = _dim_delta(stored.siblings, cur.siblings)
    if pc == "changed" or dims["changed"]:
        state = "changed"
    elif pc == "unverifiable":
        state = "unverifiable"
    else:
        state = "unchanged"
    return {"state": state, "pseudocode": pc, "dimensions": dims}


@dataclass(frozen=True)
class UpsertResult:
    """What a write reports: whether it inserted or overwrote, and (on overwrite) the prior
    annotation's attribution + timestamp so the caller can echo 'overwriting X (updated_at=T)'."""

    action: str  # 'inserted' | 'updated'
    id: int
    basis_resolved: bool
    prior_attributed_to: str | None = None
    prior_updated_at: str | None = None


def _run_id_from_ref(anchor_ref: str) -> str | None:
    """The firmware run an anchor belongs to: everything before the first ``#``, else None.

    Derived, never invented — an anchor with no run segment (or an empty one) stays NULL rather
    than being guessed at. This MUST agree with the backfill in the atlas migration, so a row
    written today and a row migrated from before the column existed carry the same value."""
    head = anchor_ref.split("#", 1)[0] if "#" in anchor_ref else ""
    return head or None


def upsert_overlay(
    atlas: sqlite3.Connection,
    *,
    evidence_ref: str,
    verdict: str,
    rationale: str,
    attributed_to: str | None = "agent-via-mcp",
    commit: bool = True,
) -> UpsertResult:
    """Write (or overwrite) the annotation for one ``evidence_ref`` — last write wins, one row per
    anchor. Rejects an unknown verdict, a blank rationale, or a fabricated attribution. Snapshots
    the candidate's basis at write time (a blind write on an unresolved ref is allowed — recording
    before a scan exists — reports ``basis_resolved=False``). Touches ONLY the overlay table."""
    if verdict not in _VERDICTS:
        raise ConfigError(f"verdict must be one of {list(_VERDICTS)}; got {verdict!r}")
    if not (rationale and rationale.strip()):
        raise ConfigError("rationale must be non-blank (why + next step + confidence)")
    if attributed_to is not None and attributed_to not in _ATTRIBUTION:
        raise ConfigError(
            f"attributed_to must be NULL or one of {list(_ATTRIBUTION)} (never fabricated)"
        )
    basis = capture_basis(atlas, evidence_ref)
    prior = atlas.execute(
        "SELECT id, attributed_to, updated_at FROM overlay "
        "WHERE anchor_kind = 'evidence_ref' AND anchor_ref = ?",
        (evidence_ref,),
    ).fetchone()
    if prior is not None:
        atlas.execute(
            "UPDATE overlay SET verdict = ?, rationale = ?, attributed_to = ?, basis_state = ?, "
            "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (verdict, rationale.strip(), attributed_to, basis.to_json(), prior["id"]),
        )
        result = UpsertResult(
            action="updated",
            id=int(prior["id"]),
            basis_resolved=basis.resolved,
            prior_attributed_to=prior["attributed_to"],
            prior_updated_at=prior["updated_at"],
        )
    else:
        cur = atlas.execute(
            "INSERT INTO overlay (anchor_kind, anchor_ref, run_id, verdict, rationale, "
            "attributed_to, basis_state) VALUES ('evidence_ref', ?, ?, ?, ?, ?, ?)",
            (
                evidence_ref,
                _run_id_from_ref(evidence_ref),
                verdict,
                rationale.strip(),
                attributed_to,
                basis.to_json(),
            ),
        )
        new_id = cur.lastrowid
        assert new_id is not None
        result = UpsertResult(action="inserted", id=new_id, basis_resolved=basis.resolved)
    if commit:
        atlas.commit()
    return result


def clear_overlay(
    atlas: sqlite3.Connection,
    *,
    run_id: str | None = None,
    evidence_ref: str | None = None,
    commit: bool = True,
) -> int:
    """Delete annotations and return how many rows went. The base map is untouched either way, so
    it reads byte-identical afterward — this is scratch space a consumer owns and may clear.

    With no scope this wipes every annotation, which is the original behaviour. Pass ONE scope to
    clear less: ``run_id`` drops one firmware's annotations, ``evidence_ref`` drops the single
    annotation on one candidate. Keeping a layer that stores conclusions tidy means retiring
    individual entries, not starting over, so the narrow forms are the ones to reach for.

    The two scopes are mutually exclusive: accepting both would have to invent a meaning for their
    combination, and guessing wrong here deletes the consumer's own work."""
    if run_id is not None and evidence_ref is not None:
        raise ConfigError(
            "clear_overlay takes at most one scope: run_id OR evidence_ref, never both"
        )
    if evidence_ref is not None:
        cur = atlas.execute(
            "DELETE FROM overlay WHERE anchor_kind = 'evidence_ref' AND anchor_ref = ?",
            (evidence_ref,),
        )
    elif run_id is not None:
        cur = atlas.execute("DELETE FROM overlay WHERE run_id = ?", (run_id,))
    else:
        cur = atlas.execute("DELETE FROM overlay")
    if commit:
        atlas.commit()
    return cur.rowcount


_STALE_NOTE = {
    "unchanged": "basis unchanged since the annotation",
    "changed": "basis CHANGED since the annotation — re-review",
    "unverifiable": "basis cannot be fully verified (no pseudocode hash) — not a clean 'unchanged'",
    "anchor_unresolved": "the anchor no longer resolves to any candidate — re-check the ref",
}

_LIST_NOTE = (
    "An AGENT annotation layer over the read-only candidate map — consumer decisions, NOT tool "
    "tool facts, and the base map is unchanged whether this is empty or full. Each row carries a "
    "basis_state: 'unchanged' means the pseudocode + dimensions the annotation rested on have not "
    "moved; 'changed' means they have (re-review); 'unverifiable' is an honest can't-say, never a "
    "clean bill; 'anchor_unresolved' means the ref no longer resolves. Stale rows are surfaced, "
    "never dropped. 'bias' is the opt-in view float(+1)/sink(-1); base-map order is untouched."
)


def list_overlays(
    atlas: sqlite3.Connection, *, verdict: str | None = None, run_id: str | None = None
) -> dict[str, Any]:
    """Every annotation, optionally narrowed to one verdict and/or one firmware run (the resume
    view: 'what did I mark inconclusive / suspicious / excluded, on THIS firmware'). Each row
    carries its live basis_state so a stale annotation is visibly flagged, never silently trusted.

    The two filters AND together. ``run_id`` is an exact match on the stored column — the run is a
    real field here, not a prefix of the anchor string, so nothing depends on how the anchor
    happens to be punctuated."""
    params: list[str] = []
    conds: list[str] = []
    if verdict is not None:
        if verdict not in _VERDICTS:
            raise ConfigError(f"verdict must be one of {list(_VERDICTS)}; got {verdict!r}")
        conds.append("verdict = ?")
        params.append(verdict)
    if run_id is not None:
        conds.append("run_id = ?")
        params.append(run_id)
    clause = ("WHERE " + " AND ".join(conds)) if conds else ""
    rows = atlas.execute(
        "SELECT id, anchor_kind, anchor_ref, run_id, verdict, rationale, attributed_to, "
        f"basis_state, created_at, updated_at FROM overlay {clause} "  # noqa: S608
        "ORDER BY verdict, updated_at DESC",
        params,
    ).fetchall()
    overlays = []
    counts: dict[str, int] = {}
    for r in rows:
        delta = basis_delta(atlas, r["anchor_ref"], Basis.from_json(r["basis_state"]))
        overlays.append(
            {
                "id": r["id"],
                "anchor_kind": r["anchor_kind"],
                "anchor_ref": r["anchor_ref"],
                "run_id": r["run_id"],  # which firmware this annotation is about
                "verdict": r["verdict"],
                "attributed_to": r["attributed_to"],
                "rationale": r["rationale"],
                # A verdict this build does not know — a word retired since the row was written —
                # falls back to neutral rather than raising. Reading an old annotation must never
                # fail just because the vocabulary moved on.
                "bias": _VERDICT_BIAS.get(r["verdict"], 0),
                "basis_state": delta["state"],
                "basis_note": _STALE_NOTE.get(delta["state"], ""),
                "basis_delta": delta,
                "updated_at": r["updated_at"],
            }
        )
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {
        "overlays": overlays,
        "count": len(overlays),
        "counts_by_verdict": counts,
        "filter": {"verdict": verdict, "run_id": run_id},
        "note": _LIST_NOTE,
    }
