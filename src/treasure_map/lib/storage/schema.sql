-- Treasure Map analysis database schema
-- Adapted from treasure-map-history database/schema.sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Round C: supersede inherited standalone script tables (dormant, never populated).
DROP TABLE IF EXISTS script_calls;
DROP TABLE IF EXISTS scripts;

-- 二进制文件
CREATE TABLE IF NOT EXISTS binaries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    path         TEXT,
    arch         TEXT,                     -- Ghidra 处理器串: ARM:LE:32:v7
    bits         INTEGER,                  -- 32 or 64
    sha256       TEXT    UNIQUE,           -- content-identity; same content → one row
    file_type    TEXT,                     -- executable / shared_library / relocatable
    dt_needed    TEXT    DEFAULT '[]',     -- JSON: DT_NEEDED 动态库依赖
    capa_tags    TEXT    DEFAULT '[]',     -- JSON: 二进制级 Capa 能力标签
    protections  TEXT    DEFAULT '{}',     -- JSON: {nx, pie, canary, relro, fortify}
    size_bytes   INTEGER DEFAULT 0,        -- ELF 文件大小 (bytes)
    ghidra_ok    INTEGER NOT NULL DEFAULT 0, -- Round 2 partial-invalidation flag (1 = usable output)
    ghidra_status TEXT,                    -- tri-state analysis outcome: ok / ok_empty / failed / NULL
    ghidra_status_reason TEXT,             -- WHY a failed run failed: timeout / import_failed /
                                           --   no_output / incomplete; NULL on success. Lets the
                                           --   incomplete surfacing distinguish a recoverable
                                           --   timeout from a structural failure
    pass_version TEXT,                     -- content hash of the ExportFunctions pass that produced
                                           --   this row's output; a mismatch re-dirties it so a pass
                                           --   edit re-extracts automatically (no manual JSON delete)
    ghidra_version TEXT,                   -- Ghidra version that produced this row's output ('unknown'
                                           --   when undetectable, NULL when produced before this was
                                           --   recorded); rolled up per run so a cross-version diff
                                           --   can tell a decompiler change from a firmware change
    strings_total     INTEGER,             -- true count of matching defined strings (>= stored); NULL
                                           --   on binaries exported before honest truncation existed
    strings_truncated INTEGER DEFAULT 0,   -- 1 = the stored strings list is a prefix (cap/cancel hit),
                                           --   so get_strings must not read a missing string as absent
    last_seen_at DATETIME,                 -- timestamp of most recent ingest scan
    analyzed_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- current_binaries: rows whose last_seen_at equals the most recent scan
-- Use this view for all "current firmware" queries; do not join binaries directly.
CREATE VIEW IF NOT EXISTS current_binaries AS
  SELECT * FROM binaries
  WHERE last_seen_at = (SELECT MAX(last_seen_at) FROM binaries);

-- 函数
CREATE TABLE IF NOT EXISTS functions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id       INTEGER NOT NULL,
    name            TEXT,
    address         TEXT,
    size_bytes      INTEGER DEFAULT 0,
    pseudocode      TEXT,               -- Ghidra 反编译 C 伪代码
    pseudocode_hash TEXT,               -- MD5，用于去重
    callees         TEXT    DEFAULT '[]',   -- JSON: 直接被调函数名
    callees_truncated INTEGER DEFAULT 0,    -- 1 = callee list hit the extractor cap (a wide dispatcher):
                                            --   the list is a prefix, so get_callees / reverse-caller
                                            --   synthesis must not read it as the complete call graph
    is_exported     INTEGER DEFAULT 0,      -- 1 = 导出符号
    -- sink_arg_provenance: Ghidra def-use fact per command/format sink in this function (JSON array,
    -- one record per sink; see ExportFunctions.buildSinkProvenance / the provenance design). TRANSPORT column:
    -- analysis.db is wipe-and-rebuild, so this rides with the function here and is merged into the
    -- atlas instance's flow_evidence at hunt time (the persistent home). Empty '[]' when none.
    sink_provenance TEXT    DEFAULT '[]',
    -- gap② phase 1: per-function nvram read/write ops (which key this function reads/writes + the
    -- written value's source). Feeds the phase-2 cross-binary key graph. Empty '[]' when none.
    nvram_ops       TEXT    DEFAULT '[]',
    -- gap② A2: JSON {op,api} when this function is a THIN nvram wrapper (forwards a caller-supplied
    -- key into one nvram accessor); NULL otherwise. Feeds hunt-time wrapper-indirect edge recovery.
    nvram_wrapper   TEXT,
    -- gap② A2: JSON [{callee,key,key_kind}] — calls to a local function passing a CONSTANT literal
    -- as arg0. Resolved against nvram_wrapper cross-function at hunt time into wrapper-indirect edges.
    wrapper_call_args TEXT DEFAULT '[]',
    -- string-keyed edges: JSON {edges:[{key,mechanism,callees:[{name,addr,kind}],...}],completeness}
    -- recovered from a same-variable strcmp ladder in this function (detector B). TRANSPORT column,
    -- flattened into the atlas string_keyed_edge table at hunt time. Empty '{}' when none.
    string_keyed_edges TEXT DEFAULT '{}',
    -- address-taken FACTS: JSON {edges:[{taken_at,taken_in_func,taken_in_func_addr,segment,
    -- nearby_symbol}],truncated} — who references THIS function's ENTRY as a data/pointer ref (a
    -- .data dispatch-table slot or a .text literal-pool `ldr =F`). Filtered by reference type
    -- (non-call, non-flow), NEVER by source segment. A FACT (F's address is taken here, by this
    -- function), NEVER a dispatch/reachability verdict. Read via get_xrefs(direction=address_taken).
    address_taken   TEXT DEFAULT '{}',
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

-- 导入符号
CREATE TABLE IF NOT EXISTS imports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL,
    func_name   TEXT,
    lib_soname  TEXT    DEFAULT '',
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

-- 导出符号
CREATE TABLE IF NOT EXISTS exports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL,
    func_name   TEXT,
    address     TEXT,
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

-- 跨库交叉引用
CREATE TABLE IF NOT EXISTS xrefs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    caller_binary_id    INTEGER,
    caller_func_id      INTEGER,        -- NULL = 库级别引用
    callee_binary_id    INTEGER,
    callee_func_id      INTEGER,        -- NULL = 库级别引用
    xref_type           TEXT,           -- import_export / dt_needed / string_ipc
    confidence          REAL    DEFAULT 1.0
);

-- xref_folded_symbols: an EXPLICIT ledger of the high-fan-out L0 export names whose per-edge
-- expansion was constrained (a generic symbol exported by many binaries × called by many functions
-- would produce a low-value edge explosion). These edges are NOT written to xrefs — but they are
-- NEVER silently dropped: this table records what was folded and how much, so a consumer can see
-- "N edges were suppressed for symbol X" and ask for them if needed. Wipe-and-rebuilt with xrefs.
CREATE TABLE IF NOT EXISTS xref_folded_symbols (
    symbol         TEXT PRIMARY KEY,   -- the folded export name (a generic high-fan-out symbol)
    exporters      INTEGER NOT NULL,   -- # binaries exporting it (with a concrete function body)
    callers        INTEGER NOT NULL,   -- # caller-function references to it across the firmware
    folded_edges   INTEGER NOT NULL    -- # L0 edges NOT materialized (the constrained edges, visible)
);

-- 字符串
CREATE TABLE IF NOT EXISTS strings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL,
    value       TEXT,
    address     TEXT,
    category    TEXT,   -- crypto_hint / ipc_sock / url / path / nvram_key / misc
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

-- naming-bridge phase 1: the router_defaults data-segment table — one row per web-settable nvram
-- default key (parsed from libshared's 20-byte struct array). A resolved member has key=name; a
-- member whose name ptr was unreadable is recorded with key=NULL (not silently skipped), so a
-- located-but-incomplete table is honest. NO rows for a binary means the symbol was not located
-- there (unknown — NEVER "no web-settable keys").
CREATE TABLE IF NOT EXISTS nvram_defaults (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id     INTEGER,
    key           TEXT,           -- member name (web-settable default key); NULL = unresolved member
    default_value TEXT,           -- member value (nullable — a null default is legitimate)
    flags         INTEGER,        -- member third field (offset 8)
    member_index  INTEGER,        -- position in the table (reproducible / debug)
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

-- string_tables (detector A transport): static {string -> funcptr} dispatch tables recovered from
-- the data segments (one row per entry). A deterministic edge fact (a string key selects a handler),
-- flattened at hunt time into the atlas string_keyed_edge table (mechanism='static_string_table').
-- The detector is incomplete by construction (MVP absolute-2-field only) — the completeness_* columns
-- carry that honestly onto every row. WIPE-AND-REBUILD per binary each analyze run.
CREATE TABLE IF NOT EXISTS string_tables (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id           INTEGER,
    table_addr          TEXT,       -- table base address (groups a table's entries)
    stride              INTEGER,    -- record stride in bytes (2*ptrsize for the MVP form)
    entry_index         INTEGER,    -- position within the table (reproducible / debug)
    key                 TEXT,       -- the dispatch string key (attacker-influenceable)
    func_name           TEXT,       -- the handler function name (BinDiff-alignable anchor)
    func_addr           TEXT,       -- the handler entry address (0x…)
    func_kind           TEXT,       -- direct | thunk | undefined_text (a .text entry Ghidra never
                                    --   turned into a function — a dispatch table is often the
                                    --   handler's ONLY reference, so nothing calls it directly)
    completeness_status TEXT,       -- always 'incomplete' this phase (MVP absolute-2-field only)
    completeness_reason TEXT,
    completeness_scope  TEXT,
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

-- detector_scan_status: ONE row per (binary, detector) written on EVERY analyze — even at 0 tables.
-- This is the honesty fix for the static string-table detector: at zero rows string_tables carries
-- nothing, so an empty result reads as "confirmed none" and conflates (a) genuinely none of the
-- SUPPORTED form, (b) a table present in an unsupported form, (c) a scan truncated by a cap. This
-- row lets a consumer tell those apart: scanned=1 + supported_scope + cap_hit make an empty result
-- carry its own honesty instead of a silent false negative.
CREATE TABLE IF NOT EXISTS detector_scan_status (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id        INTEGER NOT NULL,
    detector         TEXT    NOT NULL,   -- 'string_tables' (room for future table-form detectors)
    scanned          INTEGER NOT NULL DEFAULT 0,  -- 1 = the detector ran on this binary
    supported_scope  TEXT,              -- form(s) checked, e.g. 'absolute_2field_only'
    unsupported_note TEXT,              -- forms NOT checked (the detector's fixed reason string)
    cap_hit          INTEGER NOT NULL DEFAULT 0,  -- 1 = a probe/entry cap truncated the scan
    found_count      INTEGER NOT NULL DEFAULT 0,  -- number of tables found
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_detscan_binary ON detector_scan_status(binary_id);

-- 非二进制文件主表 (Round C framework; WIPE-AND-REBUILD each analyze run)
-- sha256 = cross-firmware identity key for the knowledge base. Indexed,
-- intentionally NOT unique (a file + its copy at another path are two findings).
CREATE TABLE IF NOT EXISTS non_binary_files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,    -- shell_script / config_file / credential / web_asset / kernel_module
    subtype      TEXT,                -- ingester-specific, e.g. shell interpreter: bash/sh/ash
    name         TEXT    NOT NULL,
    path         TEXT,                -- relative to firmware fs_root
    sha256       TEXT,                -- content identity
    size_bytes   INTEGER DEFAULT 0,
    detected_via TEXT                 -- shebang / extension / heuristic
);

-- 脚本命令调用 (ShellScript ingester sub-table; FK -> non_binary_files)
CREATE TABLE IF NOT EXISTS script_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL,
    command         TEXT,
    raw_line        TEXT,             -- script's OWN source line; analysis evidence, never a generated payload
    line_number     INTEGER,
    args_pattern    TEXT,             -- coarse structural token only: literal / var_expansion / piped
    FOREIGN KEY(file_id) REFERENCES non_binary_files(id) ON DELETE CASCADE
);

-- 配置文件条目 (ConfigFile ingester sub-table, Round D; FK -> non_binary_files)
-- Flagged-only: one row per security-relevant entry. value is evidence of
-- firmware content, never a generated payload. Export/case-study paths MUST redact
-- sensitive values + vendor strings.
CREATE TABLE IF NOT EXISTS config_entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      INTEGER NOT NULL,
    section      TEXT,                -- INI section, or NULL if sectionless
    key          TEXT,
    value        TEXT,                -- raw value (evidence of firmware content)
    is_sensitive INTEGER DEFAULT 0,   -- 1 = hardcoded-credential candidate
    FOREIGN KEY(file_id) REFERENCES non_binary_files(id) ON DELETE CASCADE
);

-- 第三方组件 + 版本（M5 CVE 匹配用）
CREATE TABLE IF NOT EXISTS components (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL,
    product     TEXT,
    version     TEXT,
    cpe         TEXT,
    source      TEXT,
    evidence    TEXT,
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

-- CVE 匹配结果（M5）
CREATE TABLE IF NOT EXISTS cve_matches (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER,
    binary_id    INTEGER,
    cve_id       TEXT,
    cvss_score   REAL,
    severity     TEXT,
    summary      TEXT,
    published    TEXT,
    url          TEXT,
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE,
    FOREIGN KEY(binary_id)    REFERENCES binaries(id)   ON DELETE CASCADE
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_functions_name     ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_binary   ON functions(binary_id);
CREATE INDEX IF NOT EXISTS idx_exports_func       ON exports(func_name);
CREATE INDEX IF NOT EXISTS idx_imports_binary     ON imports(binary_id);
CREATE INDEX IF NOT EXISTS idx_imports_soname     ON imports(lib_soname);
CREATE INDEX IF NOT EXISTS idx_xrefs_caller       ON xrefs(caller_binary_id);
CREATE INDEX IF NOT EXISTS idx_xrefs_callee       ON xrefs(callee_binary_id);
CREATE INDEX IF NOT EXISTS idx_strings_category   ON strings(category);
CREATE INDEX IF NOT EXISTS idx_strings_binary     ON strings(binary_id);
CREATE INDEX IF NOT EXISTS idx_nbf_kind          ON non_binary_files(kind);
CREATE INDEX IF NOT EXISTS idx_nbf_sha256        ON non_binary_files(sha256);
CREATE INDEX IF NOT EXISTS idx_script_calls_file ON script_calls(file_id);
CREATE INDEX IF NOT EXISTS idx_script_calls_cmd  ON script_calls(command);
CREATE INDEX IF NOT EXISTS idx_config_entries_file ON config_entries(file_id);

-- 凭据条目 (Credential ingester sub-table, Round E; FK -> non_binary_files)
-- Stores the observed artifact as verifiable evidence (deterministically
-- re-derivable from the firmware). is_sensitive=1 flags material that the
-- export/case-study/commit path MUST redact before publishing. Treasure Map
-- never GENERATES attack output (PoC/cracker/key-recovery/decryption).
CREATE TABLE IF NOT EXISTS credentials (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      INTEGER NOT NULL,
    cred_type    TEXT,                -- private_key / certificate / public_key / passwd_entry / shadow_entry
    identifier   TEXT,                -- username / cert subject / key label (non-secret); NULL if none
    algorithm    TEXT,                -- rsa_private / ec_private / sha512crypt / md5crypt / des / yescrypt / ...
    material     TEXT,                -- the observed artifact (PEM body / hash field) — evidence; redact on export
    is_sensitive INTEGER DEFAULT 0,   -- 1 = private key or password hash present (redact before publishing)
    FOREIGN KEY(file_id) REFERENCES non_binary_files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_credentials_file ON credentials(file_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(cred_type);

-- Web 端点 (WebAsset ingester sub-table, Round F; FK -> non_binary_files)
-- Attack-surface evidence: endpoints the firmware's web assets reference. path is the
-- asset's OWN content (evidence), not generated. vuln_hint is categorical.
CREATE TABLE IF NOT EXISTS web_endpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id     INTEGER NOT NULL,
    asset_type  TEXT,                 -- subtype: html / js / cgi / php / asp / jsp / ...
    method      TEXT,                 -- GET / POST / PUT / DELETE / NULL if not derivable
    path        TEXT,                 -- the endpoint path or URL (evidence)
    source      TEXT,                 -- fetch / xhr / axios / ajax / form / cgi_ref / literal
    FOREIGN KEY(file_id) REFERENCES non_binary_files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_web_endpoints_file ON web_endpoints(file_id);

-- Web 表单可编辑字段 (WebAsset ingester sub-table; FK -> non_binary_files)
-- SaTC front-end surface: the names of USER-EDITABLE form fields the firmware's own web assets
-- expose (<input> non-hidden / <textarea> / <select> / a JS form-value assignment / an
-- nvram_char_to_ascii form-fill). field_keyword is the asset's OWN content (evidence), never
-- generated. A read-only round-trip field (<input type=hidden> populated from nvram_get, e.g. a
-- firmware-version echo) is DELIBERATELY excluded: it is displayed, not settable. web_settable
-- crosses these against the back-end nvram_key_flow constant keys to tell an editable web key from a
-- read-only display key. NO rows for a run means the front-end was not collected (web_settable then
-- reads 'uncertain', NEVER 'not settable' — the false-negative red line).
CREATE TABLE IF NOT EXISTS web_form_fields (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id       INTEGER NOT NULL,
    field_keyword TEXT,                 -- editable form field name (the asset's OWN content)
    source_rule   TEXT,                 -- input / textarea / select / js_assign / nvram_ascii
    FOREIGN KEY(file_id) REFERENCES non_binary_files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_web_form_fields_file ON web_form_fields(file_id);
CREATE INDEX IF NOT EXISTS idx_web_form_fields_kw   ON web_form_fields(field_keyword);
CREATE INDEX IF NOT EXISTS idx_components_binary  ON components(binary_id);
CREATE INDEX IF NOT EXISTS idx_components_product ON components(product);
CREATE INDEX IF NOT EXISTS idx_cve_binary         ON cve_matches(binary_id);
CREATE INDEX IF NOT EXISTS idx_cve_severity       ON cve_matches(severity);
CREATE INDEX IF NOT EXISTS idx_cve_id             ON cve_matches(cve_id);
