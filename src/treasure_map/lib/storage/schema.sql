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
    is_exported     INTEGER DEFAULT 0,      -- 1 = 导出符号
    -- sink_arg_provenance: Ghidra def-use fact per command/format sink in this function (JSON array,
    -- one record per sink; see ExportFunctions.buildSinkProvenance / the provenance design). TRANSPORT column:
    -- analysis.db is wipe-and-rebuild, so this rides with the function here and is merged into the
    -- atlas instance's flow_evidence at hunt time (the persistent home). Empty '[]' when none.
    sink_provenance TEXT    DEFAULT '[]',
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

-- 字符串
CREATE TABLE IF NOT EXISTS strings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL,
    value       TEXT,
    address     TEXT,
    category    TEXT,   -- crypto_hint / ipc_sock / url / path / nvram_key / misc
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

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
CREATE INDEX IF NOT EXISTS idx_components_binary  ON components(binary_id);
CREATE INDEX IF NOT EXISTS idx_components_product ON components(product);
CREATE INDEX IF NOT EXISTS idx_cve_binary         ON cve_matches(binary_id);
CREATE INDEX IF NOT EXISTS idx_cve_severity       ON cve_matches(severity);
CREATE INDEX IF NOT EXISTS idx_cve_id             ON cve_matches(cve_id);
