# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Atlas database connection — open or create atlas.db.

WARNING: Moving atlas.db requires sqlite3 .backup() or WAL wal_checkpoint(TRUNCATE)
first — never a bare cp. WAL side-files (.db-wal, .db-shm) hold unmerged pages;
copying the main file without them yields "database disk image is malformed" on open.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from treasure_map.lib.atlas import overlay_schema

_SCHEMA_PATH = Path(__file__).parent.parent / "storage" / "atlas_schema.sql"


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply in-place, idempotent migrations the IF-NOT-EXISTS schema cannot.

    CREATE TABLE IF NOT EXISTS never adds a column to (or renames a column on) a table that
    already exists, so an atlas written by an older schema would keep its old shape. These
    ALTER TABLEs run only when the target column is missing, so the rows are preserved.
    """
    # Views an older schema built that this one no longer defines. The atlas is append-only and
    # never rebuilt, so a view is dropped here (before executescript) rather than just removed from
    # the schema — otherwise the stale definition would survive forever. dormant_instance /
    # public_finding / twin_candidate selected on a reachability_status the grader never emits
    # ('blocked'), so they were always empty.
    # Spelled out as literals: the static wipe guard (test_atlas) permits exactly these three.
    for stmt in (
        "DROP VIEW IF EXISTS dormant_instance",
        "DROP VIEW IF EXISTS public_finding",
        "DROP VIEW IF EXISTS twin_candidate",
    ):
        conn.execute(stmt)

    inst_cols = _column_names(conn, "instance")
    if inst_cols and "origin" not in inst_cols:
        # SQLite >= 3.25 allows ADD COLUMN with NOT NULL DEFAULT and a column-level CHECK;
        # if a build rejects the CHECK, fall back to the plain column and rely on the
        # writer-side enum validation. Existing rows take the default 'unknown'.
        try:
            conn.execute(
                "ALTER TABLE instance ADD COLUMN origin TEXT NOT NULL DEFAULT 'unknown' "
                "CHECK (origin IN ('custom','vendor_modified_oss','stock_oss_known','unknown'))"
            )
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE instance ADD COLUMN origin TEXT NOT NULL DEFAULT 'unknown'")
    # Candidate locatability (added this round): nullable TEXT columns, so existing rows simply
    # carry NULL until re-hunted. Idempotent — each ADD runs only while its column is missing.
    if inst_cols and "binary_path" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN binary_path TEXT")
    if inst_cols and "binary_content_hash" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN binary_content_hash TEXT")
    # Neutral structural fact (added this round): thin command-forwarding wrapper + the sink it
    # forwards to. Existing rows take the default 0 / NULL until re-hunted. Idempotent.
    if inst_cols and "is_thin_cmd_wrapper" not in inst_cols:
        try:
            conn.execute(
                "ALTER TABLE instance ADD COLUMN is_thin_cmd_wrapper INTEGER NOT NULL "
                "DEFAULT 0 CHECK (is_thin_cmd_wrapper IN (0,1))"
            )
        except sqlite3.OperationalError:
            conn.execute(
                "ALTER TABLE instance ADD COLUMN is_thin_cmd_wrapper INTEGER NOT NULL DEFAULT 0"
            )
    if inst_cols and "wrapped_sink" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN wrapped_sink TEXT")
    # Structured flow evidence (added this round): nullable JSON TEXT; existing rows carry NULL
    # until re-hunted. Idempotent — runs only while the column is missing.
    if inst_cols and "flow_evidence" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN flow_evidence TEXT")
    # exposure_shape (added this round): an exposure SHAPE (e.g. bare_sink), moved out of
    # blocking_mechanism so a danger form is never read as a mitigation. Nullable TEXT — old rows
    # carry NULL until re-hunted. Idempotent — runs only while the column is missing.
    if inst_cols and "exposure_shape" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN exposure_shape TEXT")

    # public_cve_pattern.origin (added this round): marks rows as externally imported material (not
    # tmap deterministic extraction). NOT NULL DEFAULT 'external_import'; existing rows take the
    # default. Idempotent — runs only while the column is missing. CHECK falls back to plain column.
    pcp_cols = _column_names(conn, "public_cve_pattern")
    if pcp_cols and "origin" not in pcp_cols:
        try:
            conn.execute(
                "ALTER TABLE public_cve_pattern ADD COLUMN origin TEXT NOT NULL "
                "DEFAULT 'external_import' CHECK (origin IN ('external_import'))"
            )
        except sqlite3.OperationalError:
            conn.execute(
                "ALTER TABLE public_cve_pattern ADD COLUMN origin TEXT NOT NULL "
                "DEFAULT 'external_import'"
            )

    pat_cols = _column_names(conn, "pattern")
    if "recurrence_breadth" in pat_cols and "device_spread" not in pat_cols:
        conn.execute("ALTER TABLE pattern RENAME COLUMN recurrence_breadth TO device_spread")
    if "device_category" in pat_cols:
        # Hard-removed (no real consumer): drop the legacy column in place. SQLite >= 3.35
        # supports DROP COLUMN; only evidence rows are protected from rebuild, not this
        # hand-filled, unconsumed field. Idempotent — runs only while the column exists.
        conn.execute("ALTER TABLE pattern DROP COLUMN device_category")

    ee_cols = _column_names(conn, "exec_edge")
    if "resolved_via" in ee_cols:
        # Hard-removed: it restated target_binary on every row, and where a symlink resolved the
        # target the link's own name is the basename of the token — derivable, so it was stored
        # twice. Dropping it from the schema stops new writes but cannot touch a table that already
        # exists, so an atlas built before that change keeps the column, holding values written
        # under the OLD meaning for as long as its runs are not re-hunted. Idempotent; none of
        # exec_edge's indexes references the column, so no index has to be dropped first.
        conn.execute("ALTER TABLE exec_edge DROP COLUMN resolved_via")

    # the thin nvram wrapper a wrapper-indirect key edge was resolved
    # through. Nullable TEXT — existing rows carry NULL (a DIRECT edge) until re-hunted. Idempotent.
    nvkf_cols = _column_names(conn, "nvram_key_flow")
    if nvkf_cols and "via_wrapper" not in nvkf_cols:
        conn.execute("ALTER TABLE nvram_key_flow ADD COLUMN via_wrapper TEXT")

    # diff_meta.micro_skipped_a/b (added this round): design-skipped micro-function counts, kept
    # SEPARATE from functions_empty (which now means real failures only). An atlas that already
    # created diff_meta needs these columns; nullable INTEGER, existing rows carry NULL. Idempotent.
    dm_cols = _column_names(conn, "diff_meta")
    if dm_cols and "micro_skipped_a" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN micro_skipped_a INTEGER")
    if dm_cols and "micro_skipped_b" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN micro_skipped_b INTEGER")

    # diff_meta.binary_a/b (added this round): the diff's per-side TARGET binary (short name), so a
    # per-binary consumer (string_keyed_edge delta) filters to the diffed binary, not the whole
    # firmware. An atlas that already created diff_meta needs these columns; nullable TEXT, existing
    # rows carry NULL (the consumer refuses rather than silently skipping the filter). Idempotent.
    if dm_cols and "binary_a" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN binary_a TEXT")
    if dm_cols and "binary_b" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN binary_b TEXT")

    # diff_meta per-binary status (added this round): the scan-side ghidra_ok/status/reason model
    # ported to diff, so a FAILED binary persists a queryable blind-spot row and the next full diff
    # can skip already-ok binaries (incremental) and retry failed ones (self-healing). diff_ok /
    # diff_attempts are NOT NULL DEFAULT (a pre-feature row takes ok=0 / attempts=0, i.e. "failed /
    # never counted" -> re-diffed next run, which backfills the columns); the rest are nullable.
    # Idempotent — each ADD runs only while its column is missing.
    if dm_cols and "diff_ok" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN diff_ok INTEGER NOT NULL DEFAULT 0")
    if dm_cols and "diff_status" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN diff_status TEXT")
    if dm_cols and "diff_status_reason" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN diff_status_reason TEXT")
    if dm_cols and "diff_attempts" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN diff_attempts INTEGER NOT NULL DEFAULT 0")
    if dm_cols and "sha256_a" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN sha256_a TEXT")
    if dm_cols and "sha256_b" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN sha256_b TEXT")
    # diff_meta call-site facts state (per side): read / bridge_absent / not_read, the build hash it
    # was read from, and the stub-table state. Nullable TEXT, no index references them; existing
    # rows carry NULL (facts never recorded) until the diff is re-run. Idempotent.
    for _dmcol in (
        "callsite_facts_a",
        "callsite_facts_b",
        "callsite_facts_hash_a",
        "callsite_facts_hash_b",
        "stub_state_a",
        "stub_state_b",
    ):
        if dm_cols and _dmcol not in dm_cols:
            conn.execute(f"ALTER TABLE diff_meta ADD COLUMN {_dmcol} TEXT")  # noqa: S608
    # diff_meta input stamps (per side + the diff code version) and the dropped-baseline marker.
    # No index references them; existing rows carry NULL (unverified) / 0 until re-diffed.
    # Idempotent.
    for _dmcol, _dmtype in (
        ("extraction_pass_a", "TEXT"),
        ("extraction_pass_b", "TEXT"),
        ("hunt_inputs_hash_a", "TEXT"),
        ("hunt_inputs_hash_b", "TEXT"),
        ("scanned_at_a", "TEXT"),
        ("scanned_at_b", "TEXT"),
        ("hunt_instances_a", "INTEGER"),
        ("hunt_instances_b", "INTEGER"),
        ("diff_code_version", "TEXT"),
        ("baseline_dropped", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if dm_cols and _dmcol not in dm_cols:
            conn.execute(f"ALTER TABLE diff_meta ADD COLUMN {_dmcol} {_dmtype}")  # noqa: S608
    # What each side's export could not represent (lib/diff/export_report): the builder used, the
    # repair counts, and BinDiff's first-vertex fallbacks; plus the per-function gap markers on the
    # presence / alignment rows. No index references them; existing rows carry NULL (not
    # recorded) until re-diffed. Idempotent.
    for _dmcol, _dmtype in (
        ("export_builder_a", "TEXT"),
        ("export_builder_b", "TEXT"),
        ("export_entry_addresses_added_a", "INTEGER"),
        ("export_entry_addresses_added_b", "INTEGER"),
        ("export_flow_graphs_dropped_a", "INTEGER"),
        ("export_flow_graphs_dropped_b", "INTEGER"),
        ("export_degenerate_functions_a", "INTEGER"),
        ("export_degenerate_functions_b", "INTEGER"),
        ("bindiff_vertex0_fallbacks", "INTEGER"),
        ("export_code_hash_a", "TEXT"),
        ("export_code_hash_b", "TEXT"),
        ("toolchain_ghidra", "TEXT"),
        ("toolchain_binexport", "TEXT"),
        ("toolchain_bindiff", "TEXT"),
        # the import-stub accounting and the export gaps split by it (lib/diff/layer0)
        ("stub_table_a", "TEXT"),
        ("stub_table_b", "TEXT"),
        ("stub_pairs", "INTEGER"),
        ("stub_a_only", "TEXT"),
        ("stub_b_only", "TEXT"),
        ("stub_pair_mismatch", "TEXT"),
        ("stub_complete_a", "INTEGER"),
        ("stub_complete_b", "INTEGER"),
        ("export_gaps_on_stubs_a", "INTEGER"),
        ("export_gaps_on_stubs_b", "INTEGER"),
        ("export_gaps_on_code_a", "INTEGER"),
        ("export_gaps_on_code_b", "INTEGER"),
    ):
        if dm_cols and _dmcol not in dm_cols:
            conn.execute(f"ALTER TABLE diff_meta ADD COLUMN {_dmcol} {_dmtype}")  # noqa: S608
    fa_cols = _column_names(conn, "function_alignment")
    for _facol, _fatype in (
        ("export_gap_a", "TEXT"),
        ("export_gap_b", "TEXT"),
        # an operand of the function written in its default form by that side's export
        ("operand_markup_incomplete_a", "INTEGER DEFAULT 0"),
        ("operand_markup_incomplete_b", "INTEGER DEFAULT 0"),
    ):
        if fa_cols and _facol not in fa_cols:
            conn.execute(f"ALTER TABLE function_alignment ADD COLUMN {_facol} {_fatype}")  # noqa: S608
    fp_cols = _column_names(conn, "function_presence")
    if fp_cols and "export_gap" not in fp_cols:
        conn.execute("ALTER TABLE function_presence ADD COLUMN export_gap TEXT")
    if fp_cols and "operand_markup_incomplete" not in fp_cols:
        conn.execute(
            "ALTER TABLE function_presence ADD COLUMN operand_markup_incomplete INTEGER DEFAULT 0"
        )
    # The counterpart probe (lib/diff/layer0.probe_counterparts). Nullable TEXT, no index
    # references them; existing rows carry NULL (not probed) until re-diffed. Idempotent.
    for _fpcol in (
        "counterpart_probe",
        "counterpart_addr",
        "presence_reason",
        "counterpart_overlap",
    ):
        if fp_cols and _fpcol not in fp_cols:
            conn.execute(f"ALTER TABLE function_presence ADD COLUMN {_fpcol} TEXT")  # noqa: S608

    # instruction_match.facts_a/b: the call-site facts at each side's matched address (JSON).
    # Nullable TEXT, no index references them; existing rows carry NULL. Idempotent.
    im_cols = _column_names(conn, "instruction_match")
    for _imcol in ("facts_a", "facts_b"):
        if im_cols and _imcol not in im_cols:
            conn.execute(f"ALTER TABLE instruction_match ADD COLUMN {_imcol} TEXT")  # noqa: S608

    # dimension_delta.binary (added this round): the diff's target binary (short name), parsed from
    # subject_key at write time, so a per-binary consumer filters on a real column instead of a
    # brittle LIKE on the subject_key prefix. An atlas that already created dimension_delta needs
    # the column; nullable TEXT, existing rows carry NULL until re-diffed. Idempotent.
    dd_cols = _column_names(conn, "dimension_delta")
    if dd_cols and "binary" not in dd_cols:
        conn.execute("ALTER TABLE dimension_delta ADD COLUMN binary TEXT")

    # Sink-overlay candidate-level columns: subject_kind='candidate' overlay rows carry
    # the honest `presence` (two states plus undetermined), the key granularity / match basis, the
    # tier-1 counterpart classification, the co-claim fold counts, BOTH sides' generation stamps and
    # the overlay logic version for a read-time staleness guard. All nullable TEXT/INTEGER, no index
    # references them, so adding them before executescript is safe (unlike dimension_delta.binary
    # above, which an index does reference).
    # Existing edge rows and any older atlas carry NULL. Idempotent; each runs only while missing.
    if dd_cols:
        for _c7col, _c7type in (
            ("presence", "TEXT"),
            ("key_granularity", "TEXT"),
            ("match_basis", "TEXT"),
            ("counterpart_call", "TEXT"),
            ("coclaimed_by", "TEXT"),
            ("a_n", "INTEGER"),
            ("b_n", "INTEGER"),
            ("hunt_commit_a", "TEXT"),
            ("hunt_commit_b", "TEXT"),
            ("build_hash_a", "TEXT"),
            ("build_hash_b", "TEXT"),
            ("hunt_instances_a", "INTEGER"),
            ("hunt_instances_b", "INTEGER"),
            ("overlay_version", "TEXT"),
            ("counterpart_callee", "TEXT"),
        ):
            if _c7col not in dd_cols:
                conn.execute(f"ALTER TABLE dimension_delta ADD COLUMN {_c7col} {_c7type}")  # noqa: S608

    # The overlay's own migrations live with its schema (lib/atlas/overlay_schema), run by
    # open_atlas after the atlas schema: they are not part of what the hunt reads or writes.

    # run.hunt_commit (added this round): which tmap commit produced this run's instances, so a
    # re-hunt can be skipped when the code that would run is the same code that already ran.
    # Nullable on purpose — a run hunted before this column existed carries NULL, which compares
    # equal to no commit and therefore re-hunts. Idempotent; runs only while the column is missing.
    run_cols = _column_names(conn, "run")
    if run_cols and "hunt_commit" not in run_cols:
        conn.execute("ALTER TABLE run ADD COLUMN hunt_commit TEXT")

    # run.hunt_instances (added this round): how many instance rows that hunt actually committed.
    # The commit stamp alone says WHO produced the result, not that the result is still in the
    # table — delete the rows by any route and the stamp keeps vouching for them. Storing the count
    # makes "what was written" a comparable value, so the skip gate can check the rows are still
    # there. Nullable: a run hunted before this column existed has no count to compare and re-hunts
    # once. Idempotent; runs only while the column is missing.
    run_cols = _column_names(conn, "run")
    if run_cols and "hunt_instances" not in run_cols:
        conn.execute("ALTER TABLE run ADD COLUMN hunt_instances INTEGER")

    # run.hunt_input_fingerprint: what the hunt read, condensed. build_hash is the extraction
    # CODE's hash, the same for every firmware a given tmap scans, so a re-scan of DIFFERENT
    # firmware into the same run looked "already hunted". Nullable: a run without it re-hunts once.
    run_cols = _column_names(conn, "run")
    if run_cols and "hunt_input_fingerprint" not in run_cols:
        conn.execute("ALTER TABLE run ADD COLUMN hunt_input_fingerprint TEXT")

    # run.hunt_code_version / run.scan_stamp: the code-content stamps that replace comparing git
    # commits for run currency. hunt_code_version is the hunt code's hash; scan_stamp is the
    # analysis.db's scan stamp the hunt copied over. Both nullable — a run hunted before they
    # existed carries NULL, which falls back to the commit. Idempotent; each runs only while its
    # column is missing.
    run_cols = _column_names(conn, "run")
    if run_cols and "hunt_code_version" not in run_cols:
        conn.execute("ALTER TABLE run ADD COLUMN hunt_code_version TEXT")

    run_cols = _column_names(conn, "run")
    if run_cols and "scan_stamp" not in run_cols:
        conn.execute("ALTER TABLE run ADD COLUMN scan_stamp TEXT")

    # run.promote_residual_binaries / run.promote_unowned_binaries: how many extracted binaries the
    # function-promotion pass left instructions outside any function in, and in no code block.
    # Nullable — a run hunted before they existed carries NULL ("not recorded"), never 0, until it
    # is re-hunted. No index references them. Idempotent; each runs only while missing.
    for _rcol in ("promote_residual_binaries", "promote_unowned_binaries"):
        if run_cols and _rcol not in _column_names(conn, "run"):
            conn.execute(f"ALTER TABLE run ADD COLUMN {_rcol} INTEGER")  # noqa: S608

    # binary_path columns (added this round). Every one of these tables scoped a row to a binary by
    # its SHORT NAME, which is a label: one firmware ships two files under the same name, so a
    # per-binary filter on the name matched both. The path is added beside the name rather than
    # replacing it — the name is still what a caller types and what the read side matches on, and
    # the existing rows keep working. NULL on a row written before the column existed, which reads
    # as "this row was scoped by name only" and is why the readers say so rather than pretend.
    # Idempotent; each runs only while its column is missing.
    for table, column in (
        ("exec_edge", "launcher_binary_path"),
        ("string_keyed_edge", "binary_path"),
        ("detector_scan_status", "binary_path"),
        ("nvram_key_flow", "binary_path"),
        ("nvram_defaults", "binary_path"),
        ("diff_meta", "binary_path_a"),
        ("diff_meta", "binary_path_b"),
    ):
        cols = _column_names(conn, table)
        if cols and column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")  # noqa: S608

    # The static-table reading's columns (added with the hunt-time table reader): the record's
    # stride, the key's phase, the handler offset and what pairs the two, on string_keyed_edge; the
    # unverified-handler and undetermined-pairing counts on detector_scan_status. NULL on a row
    # written before they existed (the extractor's own key-first reading): such a row is no
    # candidate (``string_edges.is_candidate_edge`` is false, so it gives leads as it always did),
    # but it is never a key anchor across versions, which takes a recorded pairing only.
    # Idempotent; each runs only while its column is missing.
    for table, column, decl in (
        ("string_keyed_edge", "stride_words", "INTEGER"),
        ("string_keyed_edge", "key_phase", "INTEGER"),
        ("string_keyed_edge", "handler_offset", "INTEGER"),
        ("string_keyed_edge", "pairing_basis", "TEXT"),
        ("string_keyed_edge", "pairing_conflict", "TEXT"),
        ("string_keyed_edge", "column_evidence", "TEXT"),
        ("detector_scan_status", "handler_unverified", "INTEGER"),
        ("detector_scan_status", "pairing_undetermined", "INTEGER"),
    ):
        cols = _column_names(conn, table)
        if cols and column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")  # noqa: S608


def open_atlas(db_path: Path) -> sqlite3.Connection:
    """Open (or create) the atlas SQLite database and apply the schema.

    The schema uses IF NOT EXISTS throughout, so re-applying it to an existing database is
    safe and preserves all rows. An older atlas is first brought forward in place by _migrate
    (adds instance.origin / binary_path / binary_content_hash / is_thin_cmd_wrapper /
    wrapped_sink / flow_evidence / dimension_delta.binary, renames pattern.recurrence_breadth ->
    device_spread, drops legacy pattern.device_category). The instance table is only ever moved
    forward in place — never rebuilt — so its rows and every derived count are kept. The judgement
    layer (overlay, overlay_history) is created and migrated by lib/atlas/overlay_schema.ensure,
    LAST — after the schema script, on top of the atlas tables; it is the one table that is ever
    rebuilt, once per retired CHECK, carrying every row across inside one transaction.

    ★ ORDER IS LOAD-BEARING: _migrate MUST run BEFORE executescript. The schema now carries an
    index/constraint that references a MIGRATED-IN column (idx_dimdelta_bin on
    dimension_delta(diff_id, binary)); on an OLD atlas whose dimension_delta predates that column,
    running executescript first hits `CREATE INDEX ... (binary)` — IF NOT EXISTS guards only the
    index NAME, not the referenced column — and raises "no such column: binary", so executescript
    aborts and _migrate never runs: the atlas cannot be opened at all. Migrating first adds the
    column, so the later CREATE INDEX finds it. On a fresh DB every _migrate step is a no-op
    (_column_names returns empty for a table that does not exist yet), so this order is safe both
    ways. Do NOT reorder these two lines — any future schema object that references a migrated
    column would silently re-break every existing atlas.

    WARNING: Moving atlas.db requires sqlite3 .backup() or wal_checkpoint(TRUNCATE)
    before any file-copy — never a bare cp while WAL side-files exist.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # 30s, not the default 5: a write (an annotation) that meets another writer's short transaction
    # waits it out instead of failing. Opening and reading never wait — _migrate writes only when
    # there is something to migrate, so an up-to-date atlas opens without the write lock.
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    schema = _SCHEMA_PATH.read_text()
    _migrate(conn)  # ★ BEFORE executescript — see the load-bearing-order note above
    conn.executescript(schema)
    conn.commit()
    overlay_schema.ensure(conn)  # ★ AFTER the atlas schema — see lib/atlas/overlay_schema
    return conn
