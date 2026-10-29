# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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

TWO ANCHOR KINDS share the table and the write path, each with its own vocabulary:

  * ``evidence_ref`` — a judgement on one candidate (the above). Candidate verdicts only.
  * ``diff_subject`` — a judgement on one entry of a version diff's function-level view
    (lib/query/patch_view): did this change do something real. Diff verdicts only; its basis is the
    entry's own diff facts (lib/query/diff_annotations), never the candidate snapshot above, and it
    reads the diff tables without writing them.

A diff verdict is refused on a candidate and a candidate verdict on a diff entry. ``promote`` is the
one way across: it carries a judgement reached on a diff entry onto one of that entry's candidates,
as a candidate verdict, after checking the entry can say what it would be taken to say, and records
where it came from (``promoted_from``) so a later read can tell when that diff stops being current.
"""

from __future__ import annotations

import json
import re
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
#
# ``exploitable`` is a tier above ``suspicious``: the digging is finished and only real-machine
# confirmation is left. Its display bias is +1 like any float verdict — what puts it ABOVE
# suspicious is its own ordering band in the view layer, deliberately kept separate from this
# number, which nothing sorts by.
_VERDICTS = ("inconclusive", "suspicious", "excluded", "safe", "exploitable")
_VERDICT_BIAS = {
    "inconclusive": 0,
    "suspicious": 1,
    "excluded": -1,
    "safe": -1,
    "exploitable": 1,
}
# The verdicts a judgement on a DIFF ENTRY may carry. A different question from the candidate
# verdicts above — not "can this be reached" but "did this change do something real" — so a
# different vocabulary, written onto a ``diff_subject`` anchor only. ``change_inconclusive`` is the
# diff side's ``inconclusive``: looked at, could not decide, and it stays in view.
_DIFF_VERDICTS = ("changed_real", "no_real_change", "change_inconclusive")
_ANCHOR_KINDS = ("evidence_ref", "diff_subject")
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


# A "does this look like it names code" probe for an exploit chain. Deliberately shallow: the
# snake_case arm matches ANY word containing an underscore, and technical prose is full of those, so
# a chain with no real anchor usually still passes. It is not a filter and must not be read as one —
# it shapes what gets written and nudges toward citing code, and it only stops prose carrying no
# symbol-shaped token at all. Tightening it is not currently possible either: real chains cite bare
# snake_case function names with no 0x/FUN_ prefix, and nothing mechanical separates those from an
# ordinary underscored word. If this verdict is ever made mandatory, this probe is NOT the check to
# lean on — a real one would demand flow structure (anchors joined by ->), which real chains have.
_CHAIN_ANCHOR = re.compile(
    r"0x[0-9a-fA-F]+"  # an address
    r"|FUN_[0-9a-fA-F]+|sub_[0-9a-fA-F]+"  # a decompiler's address-derived symbol
    r"|\b[0-9a-fA-F]{6,}\b"  # a bare hex address
    r"|\b[A-Za-z_][A-Za-z0-9]*_[A-Za-z0-9_]+\b",  # a snake_case symbol
    re.I,
)

_SAFE_FIELDS = ("block_source", "block_point", "block_why")


def _validate_verdict_basis(verdict: str, vb: dict[str, Any] | None) -> str | None:
    """Check the justification a verdict must carry, and return it as JSON to store (or None).

    Two verdicts make a claim strong enough to owe an explanation, and they owe different ones:

    * ``safe`` REQUIRES all three parts. Saying a candidate is safe is the one judgement that takes
      it off the table, and a wrong one only comes back when the CODE changes — never because the
      judgement itself was wrong. So it has to name what is blocked, where, and why that holds.
    * ``exploitable`` validates what it is GIVEN but does not yet require it. The shape is still
      being learned from real cases; making it mandatory before it has settled would push people
      into writing filler to satisfy a form.

    ★ Honest limit: these are non-blank checks. Filler passes every one of them. They are a speed
    bump and a way to make the resulting record re-usable — never evidence that the claim is true.
    """
    if verdict == "safe":
        if not vb:
            raise ConfigError(
                "safe requires verdict_basis with block_source / block_point / block_why — "
                "naming what stops the input, where, and why it cannot be bypassed"
            )
        for k in _SAFE_FIELDS:
            v = vb.get(k)
            if not (isinstance(v, str) and v.strip()):
                raise ConfigError(
                    f"safe.{k} must be non-blank (the load-bearing one is block_why: say why the "
                    "block covers every path in and cannot be worked around)"
                )
        return json.dumps({"kind": "safe", **{k: str(vb[k]).strip() for k in _SAFE_FIELDS}})

    if verdict == "exploitable":
        if vb is None:
            return None  # soft this round: recorded without a basis, by design
        chain = vb.get("chain")
        if not (isinstance(chain, str) and chain.strip()):
            raise ConfigError("exploitable.chain must be non-blank")
        if not _CHAIN_ANCHOR.search(chain):
            raise ConfigError(
                "exploitable.chain should cite code — an address, a FUN_ symbol, or a function "
                "name. This is a shallow prompt, not a check that the chain is right"
            )
        gaps = vb.get("verification_gaps")
        if not (
            isinstance(gaps, list)
            and len(gaps) >= 2
            and all(isinstance(g, str) and g.strip() for g in gaps)
        ):
            raise ConfigError(
                "exploitable.verification_gaps needs at least 2 non-blank items — what still has "
                "to be confirmed on real hardware"
            )
        sp = vb.get("shared_prereq")
        if sp is not None and not (isinstance(sp, str) and sp.strip()):
            raise ConfigError("shared_prereq, when given, must be non-blank")
        return json.dumps(
            {
                "kind": "exploitable",
                "chain": chain.strip(),
                "verification_gaps": [g.strip() for g in gaps],
                "shared_prereq": sp.strip() if isinstance(sp, str) else None,
            }
        )

    # Every other verdict carries no basis. Accepting one silently would store a justification
    # under a verdict nothing reads it for, so say so instead of dropping it.
    if vb is not None:
        raise ConfigError(f"verdict_basis applies to safe / exploitable only, not {verdict!r}")
    return None


def _validate_diff_verdict_basis(verdict: str, vb: dict[str, Any] | None) -> str | None:
    """The diff side's counterpart of ``_validate_verdict_basis`` — SHAPE only.

    ``no_real_change`` REQUIRES ``checked`` (a non-empty list of non-blank items — the facts or
    anchors read) and ``why_unchanged``. It is the verdict that sinks an entry, and like ``safe`` a
    wrong one only comes back when the diff's facts move, so it has to say what was looked at and
    why nothing real changed. ``changed_real`` MAY carry ``evidence`` (a non-empty list of non-blank
    items it rests on) and nothing else; the other verdicts carry no basis.

    ★ Shape only. The anchor threshold — that an item which looks like an anchor actually resolves
    in the diff's current view, and that at least one does — is enforced separately against the
    built view (diff_annotations.require_checked_anchor); it cannot be checked here. An anchor only
    proves the object exists in the current view, never that it was read; and the entry's own anchor
    always resolves, so these are a ranking aid, never a proof the judgement is right."""
    vb = vb or None
    if vb is not None and "evidence" in vb and verdict != "changed_real":
        raise ConfigError("evidence applies to changed_real only")
    if verdict == "no_real_change":
        if not vb:
            raise ConfigError(
                "no_real_change requires verdict_basis with checked / why_unchanged — the facts "
                "or anchors read, and why they show nothing real changed"
            )
        checked = vb.get("checked")
        if not (
            isinstance(checked, list)
            and checked
            and all(isinstance(c, str) and c.strip() for c in checked)
        ):
            raise ConfigError(
                "no_real_change.checked needs at least one non-blank item — the facts or anchors "
                "that were read to reach it"
            )
        why = vb.get("why_unchanged")
        if not (isinstance(why, str) and why.strip()):
            raise ConfigError("no_real_change.why_unchanged must be non-blank")
        return json.dumps(
            {
                "kind": "no_real_change",
                "checked": [c.strip() for c in checked],
                "why_unchanged": why.strip(),
            }
        )
    if verdict == "changed_real":
        if vb is None:
            return None
        extra = set(vb) - {"evidence"}
        if extra:
            raise ConfigError(
                "changed_real takes evidence only, not checked / why_unchanged — record what the "
                "change does in rationale"
            )
        evidence = vb.get("evidence")
        if evidence is None:
            return None
        if not (
            isinstance(evidence, list)
            and evidence
            and all(isinstance(e, str) and e.strip() for e in evidence)
        ):
            raise ConfigError(
                "changed_real.evidence needs at least one non-blank item — the facts or anchors it "
                "rests on"
            )
        return json.dumps({"kind": "changed_real", "evidence": [e.strip() for e in evidence]})
    if vb is not None:
        raise ConfigError(
            f"verdict_basis applies to no_real_change or changed_real only, not {verdict!r}"
        )
    return None


def _check_candidate_verdict(verdict: str) -> None:
    """A candidate verdict, or a refusal that says where a diff verdict goes instead."""
    if verdict in _VERDICTS:
        return
    if verdict in _DIFF_VERDICTS:
        raise ConfigError(
            f"verdict must be one of {list(_VERDICTS)} on a candidate; {verdict!r} is a diff-entry "
            "verdict and goes on a diff entry (annotate_diff)"
        )
    raise ConfigError(f"verdict must be one of {list(_VERDICTS)}; got {verdict!r}")


def _check_text_and_attribution(rationale: str, attributed_to: str | None) -> None:
    if not (rationale and rationale.strip()):
        raise ConfigError("rationale must be non-blank (why + next step + confidence)")
    if attributed_to is not None and attributed_to not in _ATTRIBUTION:
        raise ConfigError(
            f"attributed_to must be NULL or one of {list(_ATTRIBUTION)} (never fabricated)"
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


def _refuse_degraded_anchor(atlas: sqlite3.Connection, evidence_ref: str) -> None:
    """Refuse a judgement on a ref whose candidate could not be pinned to its callsite.

    The hunt marks such a candidate ``callsite_located: false``: its ref is the bare, FUNCTION-level
    anchor, and same-function siblings may share it, so a judgement written there would silently
    apply to every one of them while a single-row reader shows only the first. Refused on that
    marker alone — never on "the ref names several rows", which legitimate multi-pattern rows do."""
    for (fe,) in atlas.execute(
        "SELECT flow_evidence FROM instance WHERE evidence_ref = ?", (evidence_ref,)
    ):
        try:
            data = json.loads(fe) if fe else None
        except (ValueError, TypeError):
            continue
        if isinstance(data, dict) and data.get("callsite_located") is False:
            raise ConfigError(
                f"evidence_ref {evidence_ref!r} is a function-level degraded anchor "
                f"(callsite_located=false, anchor_degraded={data.get('anchor_degraded')!r}): "
                "several callsites may share it, so it cannot carry a per-callsite judgment"
            )


def _run_id_from_ref(anchor_ref: str) -> str | None:
    """The firmware run an anchor belongs to: everything before the first ``#``, else None.

    Derived, never invented — an anchor with no run segment (or an empty one) stays NULL rather
    than being guessed at. This MUST agree with the backfill in the atlas migration, so a row
    written today and a row migrated from before the column existed carry the same value."""
    head = anchor_ref.split("#", 1)[0] if "#" in anchor_ref else ""
    return head or None


def _write_row(
    atlas: sqlite3.Connection,
    *,
    anchor_kind: str,
    anchor_ref: str,
    verdict: str,
    rationale: str,
    attributed_to: str | None,
    basis_state: str,
    verdict_basis: str | None,
    promoted_from: str | None,
    basis_resolved: bool,
) -> UpsertResult:
    """Insert or overwrite the one row of ``(anchor_kind, anchor_ref)``, validated by the caller.

    ★ ``promoted_from`` is written on BOTH branches, NULL included. An overwrite that left it out
    would keep the previous write's origin on a row whose judgement no longer came from there."""
    prior = atlas.execute(
        "SELECT id, attributed_to, updated_at FROM overlay "
        "WHERE anchor_kind = ? AND anchor_ref = ?",
        (anchor_kind, anchor_ref),
    ).fetchone()
    if prior is not None:
        atlas.execute(
            "UPDATE overlay SET verdict = ?, rationale = ?, attributed_to = ?, basis_state = ?, "
            "verdict_basis = ?, promoted_from = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (
                verdict,
                rationale.strip(),
                attributed_to,
                basis_state,
                verdict_basis,
                promoted_from,
                prior["id"],
            ),
        )
        return UpsertResult(
            action="updated",
            id=int(prior["id"]),
            basis_resolved=basis_resolved,
            prior_attributed_to=prior["attributed_to"],
            prior_updated_at=prior["updated_at"],
        )
    cur = atlas.execute(
        "INSERT INTO overlay (anchor_kind, anchor_ref, run_id, verdict, rationale, "
        "attributed_to, basis_state, verdict_basis, promoted_from) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            anchor_kind,
            anchor_ref,
            _run_id_from_ref(anchor_ref),
            verdict,
            rationale.strip(),
            attributed_to,
            basis_state,
            verdict_basis,
            promoted_from,
        ),
    )
    new_id = cur.lastrowid
    assert new_id is not None
    return UpsertResult(action="inserted", id=new_id, basis_resolved=basis_resolved)


def upsert_overlay(
    atlas: sqlite3.Connection,
    *,
    evidence_ref: str,
    verdict: str,
    rationale: str,
    attributed_to: str | None = "agent-via-mcp",
    verdict_basis: dict[str, Any] | None = None,
    commit: bool = True,
    promoted_from: dict[str, Any] | None = None,
) -> UpsertResult:
    """Write (or overwrite) the annotation for one ``evidence_ref`` — last write wins, one row per
    anchor. Rejects an unknown verdict, a blank rationale, or a fabricated attribution. Snapshots
    the candidate's basis at write time (a blind write on an unresolved ref is allowed — recording
    before a scan exists — reports ``basis_resolved=False``). Touches ONLY the overlay table.

    ``verdict_basis`` carries the structured justification the strong verdicts owe — required for
    ``safe``, validated-if-given for ``exploitable``, refused for the rest. See
    ``_validate_verdict_basis`` for what each shape must contain and for the honest limits of the
    checking.

    ``promoted_from`` is passed by ``promote`` and by nothing else. Every other write stores NULL
    there, on an overwrite too: a judgement re-written by hand no longer came from the diff."""
    _check_candidate_verdict(verdict)
    basis_json = _validate_verdict_basis(verdict, verdict_basis)
    _check_text_and_attribution(rationale, attributed_to)
    _refuse_degraded_anchor(atlas, evidence_ref)
    basis = capture_basis(atlas, evidence_ref)
    result = _write_row(
        atlas,
        anchor_kind="evidence_ref",
        anchor_ref=evidence_ref,
        verdict=verdict,
        rationale=rationale,
        attributed_to=attributed_to,
        basis_state=basis.to_json(),
        verdict_basis=basis_json,
        promoted_from=json.dumps(promoted_from) if promoted_from is not None else None,
        basis_resolved=basis.resolved,
    )
    if commit:
        atlas.commit()
    return result


@dataclass(frozen=True)
class PreparedDiffWrite:
    """One diff annotation validated and snapshotted but NOT yet written — the output of the
    prepare step, the input of the write step. Splitting the two is what lets a batch validate every
    entry before it writes any (all of them or none)."""

    anchor_ref: str
    verdict: str
    rationale: str
    attributed_to: str | None
    basis_state: str
    verdict_basis: str | None


def prepare_diff_annotation(
    atlas: sqlite3.Connection,
    built: Any,
    meta: dict[str, Any],
    side_meta: Any,
    *,
    diff_id: str,
    anchor_ref: str,
    verdict: str,
    rationale: str,
    attributed_to: str | None,
    verdict_basis: dict[str, Any] | None,
    group_ref: str | None,
    group_cache: dict[str, Any] | None = None,
) -> PreparedDiffWrite:
    """Validate and snapshot one diff annotation against an already-built view — READ ONLY, no
    write, no commit. ``built`` / ``meta`` are the diff_annotations ``_built`` / ``_binary_diff``;
    ``side_meta`` is same_shape_siblings ``_meta`` (needed for a group_ref). Raises ConfigError on
    any problem. Shared by the single ``annotate_diff`` and the batch, so both validate alike.
    ``group_cache`` (see ``annotate_group_on``) lets a batch snapshot each group once."""
    basis_json = _check_diff_write(verdict, verdict_basis, rationale, attributed_to, group_ref)
    # Imported here, not at the top: the query package imports this module on its own import, so a
    # top-level import from it would run before this module had finished loading.
    from treasure_map.lib.query.diff_annotations import (
        capture_diff_basis_on,
        require_checked_anchor,
    )

    snapshot = capture_diff_basis_on(atlas, built, meta, diff_id, anchor_ref)
    if group_ref is not None:
        from treasure_map.lib.query.diff_group_freshness import annotate_group_on

        snapshot["group"] = annotate_group_on(
            atlas, built, side_meta, diff_id, anchor_ref, group_ref, cache=group_cache
        )
    if verdict == "no_real_change" and verdict_basis is not None:
        require_checked_anchor(atlas, built, meta, side_meta, verdict_basis["checked"], "checked")
    elif verdict == "changed_real" and verdict_basis is not None and "evidence" in verdict_basis:
        require_checked_anchor(atlas, built, meta, side_meta, verdict_basis["evidence"], "evidence")
    return PreparedDiffWrite(
        anchor_ref=anchor_ref,
        verdict=verdict,
        rationale=rationale,
        attributed_to=attributed_to,
        basis_state=json.dumps(snapshot, sort_keys=True),
        verdict_basis=basis_json,
    )


def _check_diff_write(
    verdict: str,
    verdict_basis: dict[str, Any] | None,
    rationale: str,
    attributed_to: str | None,
    group_ref: Any,
) -> str | None:
    """The checks every diff-side write makes before it reads anything: a diff verdict, its basis,
    the rationale and attribution, and a group_ref that is a string. Returns the basis JSON."""
    if verdict not in _DIFF_VERDICTS:
        if verdict in _VERDICTS:
            raise ConfigError(
                f"verdict must be one of {list(_DIFF_VERDICTS)} on a diff entry; {verdict!r} is a "
                "candidate verdict — annotate the candidate, or carry this entry's judgment to "
                "one of its candidates with promote"
            )
        raise ConfigError(f"verdict must be one of {list(_DIFF_VERDICTS)}; got {verdict!r}")
    basis_json = _validate_diff_verdict_basis(verdict, verdict_basis)
    _check_text_and_attribution(rationale, attributed_to)
    if group_ref is not None and not isinstance(group_ref, str):
        raise ConfigError(
            f"group_ref must be a string, not {type(group_ref).__name__} — copy it from a "
            "same_shape_siblings result"
        )
    return basis_json


def prepare_file_annotation(
    atlas: sqlite3.Connection,
    scope: Any,
    *,
    anchor_ref: str,
    verdict: str,
    rationale: str,
    attributed_to: str | None,
    verdict_basis: dict[str, Any] | None,
    group_ref: str | None,
) -> PreparedDiffWrite:
    """Validate and snapshot one judgement on a non-binary file — READ ONLY, like
    ``prepare_diff_annotation``, and written by the same ``write_prepared``. ``scope`` is
    diff_annotations ``FileScope`` (the run pair, its file subjects, and the binary diff's view
    when a ``diff_id`` named the pair). The anchor must name a file get_file_diff lists for the
    pair now; ``checked`` / ``evidence`` resolve against the pair's files, and against the diff's
    view too when there is one. A file has no same-shape group, so ``group_ref`` is refused."""
    basis_json = _check_diff_write(verdict, verdict_basis, rationale, attributed_to, group_ref)
    if group_ref is not None:
        raise ConfigError(
            "group_ref names a same-shape group of a function entry; a non-binary file has none"
        )
    from treasure_map.lib.query import diff_review as dr
    from treasure_map.lib.query.diff_annotations import require_file_checked_anchor

    if dr.split_anchor(anchor_ref, scope.run_a, scope.run_b) is None:
        raise ConfigError(
            f"{anchor_ref!r} is not an anchor of the run pair {scope.run_a}::{scope.run_b} — copy "
            "it from the file's anchor_ref in get_file_diff"
        )
    subject = scope.subjects.get(anchor_ref)
    if subject is None:
        raise ConfigError(
            f"{anchor_ref!r} names no file get_file_diff lists for {scope.run_a}::{scope.run_b} "
            "now (a file is anchored by its path, matched exactly as get_file_diff prints it)"
        )
    snapshot = dr.file_snapshot(scope.run_a, scope.run_b, subject)
    if verdict == "no_real_change" and verdict_basis is not None:
        require_file_checked_anchor(atlas, scope, verdict_basis["checked"], "checked")
    elif verdict == "changed_real" and verdict_basis is not None and "evidence" in verdict_basis:
        require_file_checked_anchor(atlas, scope, verdict_basis["evidence"], "evidence")
    return PreparedDiffWrite(
        anchor_ref=anchor_ref,
        verdict=verdict,
        rationale=rationale,
        attributed_to=attributed_to,
        basis_state=json.dumps(snapshot, sort_keys=True),
        verdict_basis=basis_json,
    )


def write_prepared(atlas: sqlite3.Connection, p: PreparedDiffWrite) -> UpsertResult:
    """Write one prepared diff annotation (upsert, no commit). ``promoted_from`` is NULL and
    ``basis_resolved`` True, as a diff write always is."""
    return _write_row(
        atlas,
        anchor_kind="diff_subject",
        anchor_ref=p.anchor_ref,
        verdict=p.verdict,
        rationale=p.rationale,
        attributed_to=p.attributed_to,
        basis_state=p.basis_state,
        verdict_basis=p.verdict_basis,
        promoted_from=None,
        basis_resolved=True,
    )


def annotate_diff(
    atlas: sqlite3.Connection,
    *,
    anchor_ref: str,
    verdict: str,
    rationale: str,
    attributed_to: str | None = "agent-via-mcp",
    verdict_basis: dict[str, Any] | None = None,
    group_ref: str | None = None,
    commit: bool = True,
    diff_id: str | None = None,
    run_pair: str | None = None,
) -> UpsertResult:
    """Write (or overwrite) the judgement on one entry of a diff's function-level view, or on one
    non-binary file of a run pair.

    Exactly one of ``diff_id`` (one binary's diff) and ``run_pair`` (``{run_a}::{run_b}``) names
    where ``anchor_ref`` is read. A function or candidate anchor needs ``diff_id``. A non-binary
    file's anchor (``{run_a}::{run_b}#non_binary#{path}``, from get_file_diff) takes ``run_pair``,
    or the ``diff_id`` of any binary diff of the same run pair; it is checked against the pair's
    files (lib/query/file_diff), whether or not a binary diff exists for it.

    ``anchor_ref`` names the entry (a function pair, a function with no counterpart, or one
    candidate row of an entry) inside ``diff_id``; get_diff_patch_view prints it on every entry.
    Refused unless it names something the view lists now — this is not a blind write: the basis
    snapshotted here is the entry's own diff facts (its alignment or presence, its bucket and its
    candidate rows), and with nothing to snapshot there would be nothing to re-check later.

    Diff verdicts only (``_DIFF_VERDICTS``); ``no_real_change`` owes a basis (see
    ``_validate_diff_verdict_basis``), and its ``checked`` must name at least one anchor that
    resolves in the view now (an item that looks like an anchor but names nothing is refused).
    ``changed_real`` may carry ``evidence``, held to the same anchor rule. The degraded-anchor
    refusal of a candidate write does not apply: it reads a candidate's flow evidence, which a diff
    entry does not have.

    ``group_ref`` (from a same_shape_siblings result) declares that this judgement also leaned on a
    same-shape group — "the other calls of this shape did not change". The group it names must be
    about this entry (hold a call of it, or be a shape this candidate has) or the write is refused.
    A snapshot of the group is stored beside the facts, and get_diff_patch_view re-checks it: a
    member moving, joining or leaving puts the judgement back in needs_recheck. Overwriting the
    judgement without ``group_ref`` again drops the group — pass it each time to keep it."""
    from treasure_map.lib.query.diff_annotations import _binary_diff, _built, file_scope
    from treasure_map.lib.query.file_diff import is_non_binary_anchor
    from treasure_map.lib.query.same_shape_siblings import _meta as _side_meta

    if (diff_id is None) == (run_pair is None):
        raise ConfigError(
            "pass exactly one of diff_id (one binary's diff, from list_diffs) or run_pair "
            "({run_a}::{run_b}, for a non-binary file's anchor)"
        )
    if is_non_binary_anchor(anchor_ref):
        scope = file_scope(atlas, diff_id=diff_id, run_pair=run_pair)
        prepared = prepare_file_annotation(
            atlas,
            scope,
            anchor_ref=anchor_ref,
            verdict=verdict,
            rationale=rationale,
            attributed_to=attributed_to,
            verdict_basis=verdict_basis,
            group_ref=group_ref,
        )
        result = write_prepared(atlas, prepared)
        if commit:
            atlas.commit()
        return result
    if diff_id is None:
        raise ConfigError(
            f"{anchor_ref!r} is a function or candidate anchor: pass diff_id (list_diffs) — "
            "run_pair takes a non-binary file's anchor only"
        )
    meta = _binary_diff(atlas, diff_id)
    built = _built(atlas, diff_id)
    side_meta = _side_meta(atlas, diff_id)
    prepared = prepare_diff_annotation(
        atlas,
        built,
        meta,
        side_meta,
        diff_id=diff_id,
        anchor_ref=anchor_ref,
        verdict=verdict,
        rationale=rationale,
        attributed_to=attributed_to,
        verdict_basis=verdict_basis,
        group_ref=group_ref,
    )
    result = write_prepared(atlas, prepared)
    if commit:
        atlas.commit()
    return result


@dataclass(frozen=True)
class PromoteResult:
    """A promoted write: the candidate write itself, and the origin stored with it."""

    written: UpsertResult
    evidence_ref: str
    promoted_from: dict[str, Any]


def promote(
    atlas: sqlite3.Connection,
    *,
    diff_id: str,
    entry_id: str,
    row_ref: str,
    verdict: str,
    rationale: str,
    verdict_basis: dict[str, Any] | None = None,
    allow_stale_source: bool = False,
    attributed_to: str | None = "agent-via-mcp",
    commit: bool = True,
) -> PromoteResult:
    """Carry a judgement reached on a diff entry onto one of its candidates, as a candidate verdict.

    ``row_ref`` is the candidate written to: the ``a_ref`` or ``b_ref`` of one of the entry's rows.
    ``entry_id`` is the entry's id in get_diff_patch_view, or its ``anchor_ref``. ``diff_id`` names
    one binary's diff; a run pair is refused, because the currency check below is per diff.

    Before anything is written, lib/query/diff_annotations.check_promotion refuses an entry that
    cannot say what the candidate verdict would be taken to say (where its rows land, whether the
    function's counterpart is determined) and a diff that is not current — unless
    ``allow_stale_source``, which is then recorded with the origin. The write itself goes through
    ``upsert_overlay``, which validates the verdict as for any candidate write.

    ★ Stricter than a plain candidate write in one place: ``exploitable`` REQUIRES its basis here.
    A promoted verdict rests on a diff the candidate's own snapshot cannot see, so the reason it
    was reached has to travel with it."""
    _check_candidate_verdict(verdict)
    if verdict == "exploitable" and verdict_basis is None:
        raise ConfigError(
            "promoting as exploitable requires verdict_basis (chain + verification_gaps): the "
            "judgment rests on a diff, and its reason has to be written down with it"
        )
    _validate_verdict_basis(verdict, verdict_basis)
    _check_text_and_attribution(rationale, attributed_to)
    from treasure_map.lib.query.diff_annotations import check_promotion

    origin = check_promotion(
        atlas,
        diff_id=diff_id,
        entry_id=entry_id,
        row_ref=row_ref,
        allow_stale_source=allow_stale_source,
    )
    written = upsert_overlay(
        atlas,
        evidence_ref=row_ref,
        verdict=verdict,
        rationale=rationale,
        attributed_to=attributed_to,
        verdict_basis=verdict_basis,
        commit=commit,
        promoted_from=origin,
    )
    return PromoteResult(written=written, evidence_ref=row_ref, promoted_from=origin)


def _check_anchor_kind(anchor_kind: str) -> None:
    if anchor_kind not in _ANCHOR_KINDS:
        raise ConfigError(f"anchor_kind must be one of {list(_ANCHOR_KINDS)}; got {anchor_kind!r}")


def clear_overlay(
    atlas: sqlite3.Connection,
    *,
    run_id: str | None = None,
    evidence_ref: str | None = None,
    anchor_ref: str | None = None,
    anchor_kind: str = "evidence_ref",
    clear_all: bool = False,
    commit: bool = True,
) -> int:
    """Delete annotations of one ``anchor_kind`` and return how many rows went. The base map is
    untouched either way, so it reads byte-identical afterward — this is scratch space a consumer
    owns and may clear.

    Pass ONE scope: ``run_id`` drops one firmware's annotations (for ``diff_subject``, one run
    pair's, written ``{run_a}::{run_b}``), ``anchor_ref`` the single annotation on one anchor, and
    ``evidence_ref`` is that same scope under the name a candidate annotation has always used.
    Keeping a layer that stores conclusions tidy means retiring individual entries, not starting
    over, so the narrow forms are the ones to reach for.

    ★ With NO scope nothing is deleted unless ``clear_all=True`` is passed explicitly: the whole-
    table wipe is a destructive act a consumer must ask for by name, never the default of a call
    that simply forgot its scope. ``clear_all`` wipes every annotation of that kind (candidate
    annotations by default; the diff-entry annotations are a separate kind, cleared only when asked
    for by name). The guard lives here, not only in the MCP layer, so a library caller cannot wipe
    the table by accident either.

    The scopes are mutually exclusive: accepting two would have to invent a meaning for their
    combination, and guessing wrong here deletes the consumer's own work."""
    _check_anchor_kind(anchor_kind)
    if sum(s is not None for s in (run_id, evidence_ref, anchor_ref)) > 1:
        raise ConfigError(
            "clear_overlay takes at most one scope: run_id OR evidence_ref OR anchor_ref, never two"
        )
    if run_id is None and evidence_ref is None and anchor_ref is None and not clear_all:
        raise ConfigError(
            "clear_overlay with no scope would wipe every annotation: pass a scope (run_id / "
            "evidence_ref / anchor_ref), or clear_all=True to delete them all on purpose"
        )
    if evidence_ref is not None and anchor_kind != "evidence_ref":
        raise ConfigError("evidence_ref names a candidate annotation; use anchor_ref for this kind")
    one = evidence_ref if evidence_ref is not None else anchor_ref
    if one is not None:
        cur = atlas.execute(
            "DELETE FROM overlay WHERE anchor_kind = ? AND anchor_ref = ?",
            (anchor_kind, one),
        )
    elif run_id is not None:
        cur = atlas.execute(
            "DELETE FROM overlay WHERE anchor_kind = ? AND run_id = ?", (anchor_kind, run_id)
        )
    else:
        cur = atlas.execute("DELETE FROM overlay WHERE anchor_kind = ?", (anchor_kind,))
    if commit:
        atlas.commit()
    return cur.rowcount


# The basis state a PROMOTED annotation reads with when the diff it was promoted from is not
# current, or is gone. The candidate's own snapshot cannot see a diff move, so this is the only way
# that shows up. It is just another state that is not 'unchanged', and every reader already treats
# such a row as due a look — the row marker, the overlay band and coverage alike.
SOURCE_DIFF_STALE = "source_diff_stale"

_STALE_NOTE = {
    "unchanged": "basis unchanged since the annotation",
    "changed": "basis CHANGED since the annotation — re-review",
    "unverifiable": "basis cannot be fully verified (no pseudocode hash) — not a clean 'unchanged'",
    "anchor_unresolved": "the anchor no longer resolves to any candidate — re-check the ref",
    SOURCE_DIFF_STALE: (
        "promoted from a diff that is not current now (or is gone) — re-check it there; "
        "promoted_from says why"
    ),
}


def promoted_sources(atlas: sqlite3.Connection, raw: dict[str, str]) -> dict[str, dict[str, Any]]:
    """For each anchor that carries a ``promoted_from``, that origin with whether its diff is
    current NOW: ``source_stale`` / ``source_stale_reason`` as every diff reader reports them, or
    null with ``source_diff_gone`` when the diff is no longer in this atlas. One staleness lookup
    shared by all of them; rows that were never promoted are not passed in and cost nothing."""
    from treasure_map.lib.query.diff_align import diffs_source_staleness  # see annotate_diff

    origins: dict[str, dict[str, Any]] = {}
    for ref, text in raw.items():
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            data = None
        origins[ref] = data if isinstance(data, dict) else {}
    wanted = sorted({o["diff_id"] for o in origins.values() if isinstance(o.get("diff_id"), str)})
    present: set[str] = set()
    for i in range(0, len(wanted), 500):
        chunk = wanted[i : i + 500]
        marks = ", ".join("?" * len(chunk))
        present.update(
            d
            for (d,) in atlas.execute(
                f"SELECT diff_id FROM diff_meta WHERE diff_id IN ({marks})",  # noqa: S608
                chunk,
            )
        )
    stale = diffs_source_staleness(atlas, present)
    out: dict[str, dict[str, Any]] = {}
    for ref, origin in origins.items():
        diff_id = origin.get("diff_id")
        if not isinstance(diff_id, str):
            now: dict[str, Any] = {"source_stale": None, "source_stale_reason": "origin_unreadable"}
        elif diff_id not in present:
            now = {"source_stale": None, "source_stale_reason": "source_diff_gone"}
        else:
            now = {k: stale[diff_id][k] for k in ("source_stale", "source_stale_reason")}
        out[ref] = {**origin, **now}
    return out


def effective_basis_state(own: str, source: dict[str, Any] | None) -> str:
    """A row's basis state once the diff it was promoted from is counted in: the worse of the two.

    Not promoted, or promoted from a diff that is current (``source_stale`` false, and only false):
    its own state. Otherwise ``source_diff_stale`` — unless its own state already says the
    candidate itself moved or is gone, which says more about the candidate and is kept."""
    if source is None or source.get("source_stale") is False:
        return own
    if own in ("anchor_unresolved", "changed"):
        return own
    return SOURCE_DIFF_STALE


_LIST_NOTE = (
    "An AGENT annotation layer over the read-only candidate map — consumer decisions, NOT tool "
    "facts, and the base map is unchanged whether this is empty or full. Each row carries a "
    "basis_state: 'unchanged' means the pseudocode + dimensions the annotation rested on have not "
    "moved; 'changed' means they have (re-review); 'unverifiable' is an honest can't-say, never a "
    "clean bill; 'anchor_unresolved' means the ref no longer resolves. Stale rows are surfaced, "
    "never dropped. 'bias' is the opt-in view float(+1)/sink(-1); base-map order is untouched."
)


def list_overlays(
    atlas: sqlite3.Connection,
    *,
    verdict: str | None = None,
    run_id: str | None = None,
    anchor_kind: str = "evidence_ref",
    file_staleness: Any = None,
) -> dict[str, Any]:
    """Every annotation of one ``anchor_kind``, optionally narrowed to one verdict and/or one
    firmware run (the resume view: 'what did I mark inconclusive / suspicious / excluded, on THIS
    firmware'). Each row carries its live basis_state so a stale annotation is visibly flagged,
    never silently trusted.

    The two filters AND together. ``run_id`` is an exact match on the stored column — the run is a
    real field here, not a prefix of the anchor string, so nothing depends on how the anchor
    happens to be punctuated.

    Candidate annotations by default. A promoted one also carries ``promoted_from`` (the diff it
    came from, the carrying row's landing + subclass, and whether that diff is current now); when it
    is not, the row reads ``source_diff_stale`` (see ``effective_basis_state``). ``diff_subject``
    lists the diff-entry annotations instead, through lib/query/diff_annotations
    (``file_staleness`` is passed to it for the judgements on non-binary files)."""
    _check_anchor_kind(anchor_kind)
    if anchor_kind == "diff_subject":
        from treasure_map.lib.query.diff_annotations import list_diff_overlays

        return list_diff_overlays(
            atlas, verdict=verdict, run_id=run_id, file_staleness=file_staleness
        )
    params: list[str] = [anchor_kind]
    conds: list[str] = ["anchor_kind = ?"]
    if verdict is not None:
        if verdict not in _VERDICTS:
            raise ConfigError(f"verdict must be one of {list(_VERDICTS)}; got {verdict!r}")
        conds.append("verdict = ?")
        params.append(verdict)
    if run_id is not None:
        conds.append("run_id = ?")
        params.append(run_id)
    clause = "WHERE " + " AND ".join(conds)
    rows = atlas.execute(
        "SELECT id, anchor_kind, anchor_ref, run_id, verdict, rationale, attributed_to, "
        "basis_state, verdict_basis, promoted_from, created_at, updated_at "
        f"FROM overlay {clause} "  # noqa: S608
        "ORDER BY verdict, updated_at DESC",
        params,
    ).fetchall()
    sources = promoted_sources(
        atlas, {r["anchor_ref"]: r["promoted_from"] for r in rows if r["promoted_from"]}
    )
    overlays = []
    counts: dict[str, int] = {}
    for r in rows:
        delta = basis_delta(atlas, r["anchor_ref"], Basis.from_json(r["basis_state"]))
        source = sources.get(r["anchor_ref"])
        state = effective_basis_state(delta["state"], source)
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
                "basis_state": state,
                "basis_note": _STALE_NOTE.get(state, ""),
                # The structured justification a safe / exploitable annotation was written with,
                # parsed back for the reader; None for verdicts that carry none.
                "verdict_basis": json.loads(r["verdict_basis"]) if r["verdict_basis"] else None,
                "basis_delta": delta,
                "updated_at": r["updated_at"],
                # Where a promoted judgement came from (the diff, the entry anchor, and the row's
                # landing + subclass), and whether that diff is current now; None on every row that
                # was not promoted.
                "promoted_from": source,
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
