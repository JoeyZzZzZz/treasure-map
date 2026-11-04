-- Copyright (C) 2026 JoeyZzZzZz
-- SPDX-License-Identifier: Apache-2.0
--
-- The judgement layer of the atlas: the overlay and its history. Created by
-- lib/atlas/overlay_schema.py (never by atlas_schema.sql), after the atlas schema, and the single
-- source of both tables' definition: a new atlas creates them from here, an older overlay is
-- rebuilt from the same statement. Kept apart from the atlas schema because the hunt neither
-- reads nor writes these tables: an edit here must not read every run as re-hunted.

-- ── overlay: a mutable annotation layer over the read-only candidate map ──────
-- Holds an AGENT's OWN annotations on scan/hunt candidates — never a tool-emitted
-- fact, and NEVER written back onto instance/pattern (which stay untouched). A
-- consumer reads the base map, decides something about a candidate, and records
-- that decision here, keyed by the candidate's evidence_ref. Two views share one
-- base map: with the overlay off (the default) the base map reads byte-for-byte
-- as if this table were empty; with it on, these annotations are shown ALONGSIDE
-- the base facts, always distinguishable from them.
--
-- The row is MUTABLE (one annotation per anchor, last write wins) — this is why
-- it lives outside the append-only instance/pattern store. basis_state snapshots
-- the facts the annotation rested on at write time (the function's pseudocode
-- hash + the per-sibling dimension set); a later read re-derives that basis and
-- reports what moved, so an annotation made against now-stale facts is flagged
-- for re-review. The layer reports those facts ONLY — whether a changed basis
-- undoes the annotation is the consumer's judgement, never asserted here.
CREATE TABLE IF NOT EXISTS overlay (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 'evidence_ref': a judgement on one candidate (anchor_ref is its evidence_ref).
    -- 'diff_subject': a judgement on one entry of a version diff's function-level view
    -- (anchor_ref is '{run_a}::{run_b}#{function_pair|function_presence|candidate}#{key}').
    anchor_kind   TEXT NOT NULL DEFAULT 'evidence_ref'
        CHECK (anchor_kind IN ('evidence_ref','diff_subject')),
    anchor_ref    TEXT NOT NULL,
    -- Which firmware this annotation belongs to. DERIVED from anchor_ref (the segment before '#'),
    -- stored explicitly so filtering to one firmware is an exact equality match instead of a
    -- string prefix probe. Nullable: an anchor kind that carries no run segment leaves it NULL
    -- rather than guessing. It does NOT change the uniqueness rule below.
    run_id        TEXT,
    -- No CHECK here on purpose. The vocabulary is still evolving, and pinning it in the schema
    -- means every wording change costs a table rebuild that has to carry real annotations across.
    -- Validity is enforced where the writes are: the sole write path is overlay.py::upsert_overlay,
    -- which validates at its head. A static gate pins that overlay writes spelled contiguously in
    -- source text, outside lib/overlay.py, are zero apart from the whitelisted migrations — text
    -- matching, so it cannot claim more than that. A second test pins that every known verdict has
    -- an ordering band, so a new one cannot slip in unhandled.
    verdict       TEXT NOT NULL,
    rationale     TEXT NOT NULL,            -- why + next step + confidence; blank is rejected at write
    attributed_to TEXT
        -- coarse provenance. 'human' = a declaration typed and confirmed on an interactive
        -- terminal of this machine (tmap review judge / audit --apply), NOT proof a person wrote
        -- it: an agent that unsets the environment markers can still claim it. 'human-via-agent'
        -- = a person's judgement written down by an agent, never raised to 'human'.
        CHECK (attributed_to IS NULL OR attributed_to IN
            ('agent','agent-via-mcp','human','human-via-agent')),
    basis_state   TEXT,                     -- JSON snapshot: pseudocode_hash + per-sibling dimension set
    -- Structured justification for the two verdicts that require one, JSON keyed by `kind`:
    -- safe {block_source, block_point, block_why} / exploitable {chain, verification_gaps,
    -- shared_prereq}. NULL for every verdict that carries none. NOT the same thing as basis_state
    -- above: that snapshots the FACTS an annotation rested on (for staleness); this records WHY the
    -- consumer reached the conclusion. Two columns, two jobs, neither written from the other.
    verdict_basis TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Where a candidate judgement came from when it was carried over from a diff entry
    -- (overlay.py::promote): JSON {diff_id, anchor_ref, landing, subclass (the carrying row's),
    -- entry_bucket, entry_subclass (the entry's; absent on an origin written before they were
    -- recorded), promoted_while_source_stale (only when allowed stale)}. NULL for every other
    -- row; any other write to the row sets it back to NULL, so a stale origin is never left
    -- behind.
    promoted_from TEXT,
    -- one annotation per anchor: a re-annotation UPDATES in place (last write wins)
    UNIQUE (anchor_kind, anchor_ref)
);
CREATE INDEX IF NOT EXISTS idx_overlay_verdict ON overlay(verdict);

-- ── overlay_history: every change to the overlay, append-only ──────────────────
-- One row per write that changes an overlay row (insert, update, promote, delete — every
-- clear_overlay scope), per migration of the table, and per shadow judgement (an audit's verdict,
-- recorded here only: it never changes the current row). ``before`` / ``after`` are the whole
-- row as JSON (NULL where there is none), so a deleted row can be restored from here. The
-- overlay keeps its last-write-wins meaning; this table is how a judgement that was overwritten,
-- disputed or cleared is still read.
CREATE TABLE IF NOT EXISTS overlay_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event         TEXT NOT NULL
        CHECK (event IN ('insert','update','promote','delete','migration','shadow')),
    overlay_id    INTEGER,                  -- the overlay row's id; NULL for a migration
    anchor_kind   TEXT,
    anchor_ref    TEXT,
    run_id        TEXT,
    before        TEXT,                     -- JSON: the whole row before, or NULL
    after         TEXT,                     -- JSON: the whole row after (a shadow's verdict), or NULL
    attributed_to TEXT,                     -- who wrote it (as the row records it)
    channel       TEXT,                     -- mcp / worksheet / judge / cli / migration
    unit_id       TEXT,                     -- the work unit it was written for, when one was named
    read_basis    TEXT,                     -- JSON: what was read before it (the tool-call log)
    session       TEXT,                     -- the writing server's session id, when known
    note          TEXT                      -- JSON: what a migration did, a delete's scope, ...
);
CREATE INDEX IF NOT EXISTS idx_overlay_history_anchor ON overlay_history(anchor_kind, anchor_ref);
CREATE INDEX IF NOT EXISTS idx_overlay_history_unit ON overlay_history(unit_id);
