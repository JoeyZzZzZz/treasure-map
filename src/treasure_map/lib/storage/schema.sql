-- Treasure Map analysis database schema
-- Adapted from treasure-map-history database/schema.sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- 二进制文件
CREATE TABLE IF NOT EXISTS binaries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    path        TEXT,
    arch        TEXT,               -- Ghidra 处理器串: ARM:LE:32:v7
    bits        INTEGER,            -- 32 or 64
    sha256      TEXT    UNIQUE,
    file_type   TEXT,               -- executable / shared_library / relocatable
    dt_needed   TEXT    DEFAULT '[]',   -- JSON: DT_NEEDED 动态库依赖
    capa_tags   TEXT    DEFAULT '[]',   -- JSON: 二进制级 Capa 能力标签
    protections TEXT    DEFAULT '{}',   -- JSON: {nx, pie, canary, relro, fortify}
    analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 函数
CREATE TABLE IF NOT EXISTS functions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id       INTEGER NOT NULL,
    name            TEXT,
    address         TEXT,
    size_bytes      INTEGER DEFAULT 0,
    pseudocode      TEXT,               -- Ghidra 反编译 C 伪代码
    pseudocode_hash TEXT,               -- MD5，用于去重
    summary         TEXT,               -- AI 一句话描述
    func_types      TEXT    DEFAULT '[]',   -- JSON: ["crypto","vuln_bof"]
    callees         TEXT    DEFAULT '[]',   -- JSON: 直接被调函数名
    vuln_hints      TEXT    DEFAULT '[]',   -- JSON: AI 漏洞提示
    capa_tags       TEXT    DEFAULT '[]',   -- JSON: 函数级 Capa 标签
    is_exported     INTEGER DEFAULT 0,      -- 1 = 导出符号
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

-- 库级摘要（AI 生成）
CREATE TABLE IF NOT EXISTS library_summaries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id       INTEGER UNIQUE,
    purpose         TEXT,
    key_algorithms  TEXT    DEFAULT '[]',   -- JSON: ["AES-128-CBC","SHA256"]
    key_functions   TEXT    DEFAULT '[]',   -- JSON: 最重要的 5 个函数名
    patch_notes     TEXT,
    FOREIGN KEY(binary_id) REFERENCES binaries(id) ON DELETE CASCADE
);

-- 脚本文件（M3 启用）
CREATE TABLE IF NOT EXISTS scripts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    path        TEXT,
    interpreter TEXT,   -- sh / bash / python / lua / perl
    sha256      TEXT UNIQUE,
    size_bytes  INTEGER,
    analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 脚本命令调用（M3 启用）
CREATE TABLE IF NOT EXISTS script_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    script_id       INTEGER NOT NULL,
    command         TEXT,
    raw_line        TEXT,
    line_number     INTEGER,
    args_pattern    TEXT,
    has_user_input  INTEGER DEFAULT 0,
    vuln_hint       TEXT,
    FOREIGN KEY(script_id) REFERENCES scripts(id) ON DELETE CASCADE
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
CREATE INDEX IF NOT EXISTS idx_functions_types    ON functions(func_types);
CREATE INDEX IF NOT EXISTS idx_functions_summary  ON functions(summary);
CREATE INDEX IF NOT EXISTS idx_functions_vuln     ON functions(vuln_hints);
CREATE INDEX IF NOT EXISTS idx_exports_func       ON exports(func_name);
CREATE INDEX IF NOT EXISTS idx_imports_binary     ON imports(binary_id);
CREATE INDEX IF NOT EXISTS idx_imports_soname     ON imports(lib_soname);
CREATE INDEX IF NOT EXISTS idx_xrefs_caller       ON xrefs(caller_binary_id);
CREATE INDEX IF NOT EXISTS idx_xrefs_callee       ON xrefs(callee_binary_id);
CREATE INDEX IF NOT EXISTS idx_strings_category   ON strings(category);
CREATE INDEX IF NOT EXISTS idx_strings_binary     ON strings(binary_id);
CREATE INDEX IF NOT EXISTS idx_script_calls_cmd   ON script_calls(command);
CREATE INDEX IF NOT EXISTS idx_script_calls_ui    ON script_calls(has_user_input);
CREATE INDEX IF NOT EXISTS idx_scripts_name       ON scripts(name);
CREATE INDEX IF NOT EXISTS idx_components_binary  ON components(binary_id);
CREATE INDEX IF NOT EXISTS idx_components_product ON components(product);
CREATE INDEX IF NOT EXISTS idx_cve_binary         ON cve_matches(binary_id);
CREATE INDEX IF NOT EXISTS idx_cve_severity       ON cve_matches(severity);
CREATE INDEX IF NOT EXISTS idx_cve_id             ON cve_matches(cve_id);
