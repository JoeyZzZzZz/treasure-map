# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-11-24

This release registers the MCP server with the official MCP registry, so a client can install it
by name, and carries a cycle of review, hunt and performance work. **No firmware is decompiled
again**: the extraction pass is byte-identical to 0.2.0, so one `tmap rescan` reuses what is
already on disk (see Upgrading from 0.2.0).

### Highlights

- **Installable from the MCP registry.** The server is published as
  `io.github.JoeyZzZzZz/treasure-map`; a client that reads the registry runs `uvx tmap-agents
  mcp`. `server.json` lives in the repository, and CI keeps it agreeing with the version, the
  distribution name and the README marker the registry verifies ownership with.
- **`tmap runs` covers diffs and deletes.** Every version diff is listed beside the scans,
  grouped by run pair, and a run, a pair's diffs or one binary diff can be deleted from the atlas.
- **A judgment says where it landed.** A `changed_real` cites the rows its change touched — also
  for a function only one side of the pair has — and an alternative pairing between two entries is
  read as an entry of its own rather than folded into one of them.
- **More of the firmware reads as reachable, honestly.** A configuration getter that parses its
  own input reads as a source and names the key it was asked for; a CGI placed in a served tree
  reads as web-reachable, with the reading marked `inferred` and its basis given.
- **An interrupt stops everything it started.** BinDiff runs in a killable process group,
  `tmap review run` kills the agent it launched and leaves no working directory, and a hangup that
  `nohup` ignored on purpose is left ignored — a closed terminal no longer ends a long scan.
- **Less memory and less disk**: a page of candidates slices one reading of the run instead of
  one per page, a diff keeps its run pair's facts once, and a scan deletes raw extractor output
  once it is ingested.

### Upgrading from 0.2.0

- Run `tmap update`, then `tmap rescan`. **Nothing is extracted again** — the extraction pass and
  both export hashes are unchanged, so the scan reuses every stored extraction and rebuilds only
  the facts above it. `tmap runs` lists what the upgrade left out of date; `tmap rescan --dry-run`
  lists what it would re-run.
- Run `tmap diff --before A --after B` again for each pair you diffed: the diff code changed, so
  a stored diff reads out of date until it is re-run.
- Run `tmap init` again — the `tmap-diff-review` agent skill changed.
- Restart your MCP client (or reconnect the `treasure-map` server) so it reads the current tool
  descriptions.

### Added

MCP registry

- `server.json` at the repository root, the `mcp-name` marker in the README (which becomes the
  PyPI description the registry reads to verify ownership), and a `tmap-agents` console script
  beside `tmap`, because a client told `runtimeHint: uvx` runs the command named after the
  package. One CI gate holds all four together, and the release validates and publishes the
  server after PyPI has the version.

Runs and atlas housekeeping

- `tmap runs` lists every version diff beside the scans, grouped by run pair with each pair's
  current / stale / unverified / failed counts (`--diffs` shows every binary under its pair).
- `--delete` removes the atlas records of a run, of a run pair's diffs, or of one binary diff.
  Repeatable and applied atomically; firmware files and workspaces are never touched.
- `tmap scan` asks before it overwrites a workspace that already holds a different firmware.

Diff review

- An alternative pairing between two entries of a pair is read as an entry of its own, and
  alternative entries join their dispatch group.
- A `changed_real` cites the rows its change landed on; the citation gate holds for a function
  only one side has. Two fact-layer gaps are named instead of passing silently.
- The findings hand-off carries open items, each with its basis, and `earlier_changed_real`.
- `clear_overlay` states in the MCP server what it is about to clear.

Hunt

- A configuration-store getter that parses its own input reads as a weak source, and the key it
  reports comes from its key argument only; a value-getter helper's own body reads it as a weak
  source too.
- A CGI placed in a served tree reads as web-reachable. The reading is marked `inferred`, and its
  note, source and evidence say what it was inferred from.

### Changed

- A page of candidates slices one reading of the run, and at most two readings are kept at a time
  (measured: 173 MB per reading on a large image).
- A per-diff cache holds the whole run pair instead of 16 or 32 entries of it.
- A scan deletes raw extractor output once it is ingested; the literal-span check is
  binary-searched and the two keyed-call passes are merged into one.
- The MCP server keeps the on-disk code hash for the process instead of re-reading it per tool
  listing.
- Internal names only: the modules, the hunt and the two diff stages are named after what they do
  (alignment, dimension delta). No response field, stored value or stage label changed.
- Retired code paths and read-layer helpers nothing reaches were removed.

### Fixed

- A hangup the parent ignored on purpose is left ignored: `nohup tmap scan … &` and a closed
  terminal no longer turn into an interrupt that ends hours of Ghidra time with exit 129.
- An interrupt kills the agent `tmap review run` launched, and the run leaves no working
  directory behind.
- BinDiff runs in a killable process group, so an interrupt stops a diff sweep at once instead of
  after the current binary.
- `tmap runs` prints one line per diff pair, with the pair's reasons on it once.
- A word that two dispatch tables of different strides both read no longer costs the wider table
  a column or a record.
- A `dsh` profile whose header mentions `!!js` is read, and one `tmap` that cannot be read no
  longer fails an uninstall.

### 亮点

- **可以从 MCP 官方 Registry 安装。** 服务器以 `io.github.JoeyZzZzZz/treasure-map` 发布；读
  Registry 的客户端运行 `uvx tmap-agents mcp`。`server.json` 放在仓库里，CI 保证它与版本号、
  发布包名、以及 Registry 用来验证归属的 README 标记始终一致。
- **`tmap runs` 管得到对比，也能删。** 每个版本对比都与扫描并列列出、按 run 对分组；一个 run、
  一对的全部对比、或单个二进制的对比都可以从 atlas 删掉。
- **判断会说清落在哪。** `changed_real` 会引用它的改动落在哪些行上 —— 只有一侧有的函数也一样 ——
  一对里两个条目之间的替代配对会作为独立条目来读，不再并进其中一个。
- **更多固件代码被读成可达，且诚实。** 自己解析输入的配置读取函数会读成 source，并说出被问的是
  哪个 key；放在对外目录树里的 CGI 读成 web 可达，该判读标为 `inferred` 并给出依据。
- **中断会停掉它启动的一切。** BinDiff 跑在可被杀掉的进程组里，`tmap review run` 会杀掉它启动的
  agent 且不留工作目录，而 `nohup` 故意忽略的挂断信号不再被夺回 —— 关掉终端不会再终止长扫描。
- **更省内存和磁盘**：一页候选只切一份 run 读数（不再每页一份），一个对比只保留一份 run 对事实，
  扫描在数据入库后删掉提取器的原始输出。

### 从 0.2.0 升级

- 运行 `tmap update`，然后 `tmap rescan`。**不会重新提取** —— 提取阶段和两个导出哈希都没变，所以
  扫描会复用已存的提取结果，只重建它上面的事实层。`tmap runs` 列出升级后哪些已过期，
  `tmap rescan --dry-run` 列出它将重跑哪些。
- 对每一对比过的版本重新运行 `tmap diff --before A --after B`：对比代码变了，已存的对比在重跑前
  读作过期。
- 再运行一次 `tmap init` —— `tmap-diff-review` agent skill 有改动。
- 重启 MCP 客户端（或重连 `treasure-map` 服务器），让它读到当前的工具说明。

### 新增

MCP Registry

- 仓库根目录的 `server.json`、README 里的 `mcp-name` 标记（它会成为 PyPI 上的包描述，Registry
  读它来验证归属），以及 `tmap` 之外新增的 `tmap-agents` 命令 —— 因为读到 `runtimeHint: uvx` 的
  客户端会运行与包同名的命令。一道 CI 闸把这四处钉在一起，发版流程在 PyPI 拿到该版本之后才校验
  并发布服务器条目。

Run 与 atlas 管理

- `tmap runs` 把每个版本对比与扫描并列列出，按 run 对分组，给出每对的 current / stale /
  unverified / failed 计数（`--diffs` 展开每对下的每个二进制）。
- `--delete` 删除一个 run、一对的全部对比、或单个二进制对比的 atlas 记录。可重复传入、原子生效；
  固件文件和工作目录绝不触碰。
- `tmap scan` 在覆盖一个已装着别的固件的工作目录前会先询问。

对比评审

- 一对里两个条目之间的替代配对会作为独立条目来读，替代条目会归入它所属的分发组。
- `changed_real` 会引用改动落在哪些行上；只有一侧有的函数也受这道引用闸约束。两处事实层缺口会被
  点名，而不是静默通过。
- 发现交接件带上未决项（各自带依据）和 `earlier_changed_real`。
- `clear_overlay` 在 MCP 服务器里说明它将要清掉什么。

Hunt

- 自己解析输入的配置读取函数读成弱 source，它报出的 key 只来自它的 key 实参；取值辅助函数自己的
  函数体也把它读成弱 source。
- 放在对外目录树里的 CGI 读成 web 可达。该判读标为 `inferred`，其 note、source 和 evidence 都说明
  是据什么推断的。

### 变更

- 一页候选只切一份 run 读数，同时最多保留两份（实测：大镜像上每份 173 MB）。
- 每个对比的缓存改为容纳整个 run 对，而不是其中 16 或 32 个条目。
- 扫描在数据入库后删掉提取器的原始输出；字面量区间检查改为二分，两遍 keyed-call 合为一遍。
- MCP 服务器把磁盘上的代码哈希按进程保留，不再每次列工具时重读。
- 只改内部名字：各模块、hunt 和两个对比阶段都按它们做的事命名（alignment、dimension delta）。
  没有任何响应字段、存储值或阶段标签改变。
- 删掉了已退休的代码路径和读层里没人用的辅助函数。

### 修复

- 父进程故意忽略的挂断信号保持被忽略：`nohup tmap scan … &` 加上关闭终端，不再变成中断、把几个
  小时的 Ghidra 时间以退出码 129 结束。
- 中断会杀掉 `tmap review run` 启动的 agent，并且该次运行不留下工作目录。
- BinDiff 跑在可被杀掉的进程组里，中断会立刻停下整轮对比，而不是等当前二进制跑完。
- `tmap runs` 每个对比对只打一行，该对的原因在这一行上只说一次。
- 两个不同步长的分发表都读到的某个词，不再让更宽的那张表损失一列或一条记录。
- 头部出现 `!!js` 的 `dsh` 配置能被读取；某一个读不了的 `tmap` 不再让卸载失败。

## [0.2.0] - 2026-11-17

This release reviews a whole version diff unit by unit and reads much more of each firmware image.
The extraction changed, so every run needs one full rescan (see Upgrading from 0.1.1).

### Highlights

- **Review a whole version diff, unit by unit.** `start_diff_review(run_pair=...)` cuts the pair
  into work units, hands out the must-read ones first and tracks coverage on the server.
  `tmap review run <run_pair> --agent claude-code` drives your agent through the units, one
  launch per unit.
- **A findings hand-off for people.** `tmap review report --handoff` and `get_diff_handoff` write
  one block per real finding: the recorded judgment and tmap's facts about it.
- **Diffs say more about each change**: strings present on one side only, evidence for uncertain
  pairings and alternative ones, line-number drift, recompile-only changes, upstream version
  bumps, and every non-binary file of both images.
- **More of the firmware is seen**: static dispatch tables, configuration getters as sources,
  programs launched through a runner function, paths passed through thin wrappers, and decoded
  ARM / AArch64 PLT stub tables.
- **Sturdier extraction**: each binary in its own session, with its BinExport archived for
  `tmap diff`; code reached only through data pointers is recovered; bytes Ghidra never
  disassembled are reported; timed-out decompiles are retried.
- **Large answers are paged** across the fact tools instead of cut.

### Upgrading from 0.1.1

- Run `tmap rescan` once. The extraction pass changed, so **every binary is decompiled again**:
  plan for a long run on a large image. An interrupted rescan keeps the binaries it finished.
- Run `tmap diff --before A --after B` again for each pair you diffed. The diff code changed, so
  every stored diff reads as out of date until it is re-run.
- Run `tmap init` again: it installs the `tmap-diff-review` agent skill.
- Restart your MCP client (or reconnect the `treasure-map` server) so it loads the new tool list.
- `analysis.db` and the atlas gain their new tables and columns automatically on first open. A
  column added this way reads "not recorded" until the rescan fills it.

### Added

Diff review

- **`start_diff_review(run_pair=...)`**: the whole pair as work units (single entries, callee
  groups — the entries that newly call one function, read together — and non-binary files) with
  a server-computed report: `coverage_statement`, the must-read units and `must_read_complete`.
  Judge each member with `annotate_diff(..., unit_id=...)` and call again until `next_unit` is
  null. Only the must-read units are handed out by default; the second tier is offered after
  them. `worker` / `workers` split a pair across sessions, and every hand-out says how far the
  pair is and how a fresh session goes on.
- **`tmap review`**: `report` (the summary, or the whole report as `--md` / `--html`), `judge` (a
  person's judgment, which becomes the current one and keeps the agent's in the history),
  `audit` (a worksheet of disagreements to settle, `--emit` / `--apply`), `run` (the batch
  driver: one launch of your agent per unit — the `claude-code` preset, experimental `codex` /
  `cursor`, or a command template — with `--max-units`, `--max-minutes`, `--worker` /
  `--workers`, `--until must_read|complete` and `--handoff FILE`) and `skill` (print or install
  the review skill).
- **`get_diff_handoff(run_pair)`** and **`tmap review report --handoff`**: a standardized
  hand-off of the pair's `changed_real` findings, one block per finding, with the judgment, the
  change, its reachable shape, its same-shape siblings and two fields a person fills in
  (`--analysis` adds an agent's texts). Served once the must-read set is complete.
- A tool-call log beside the atlas, from which the server tells which material a session read.

Diff facts

- **`get_diff_string_delta(diff_id)`**: the string literals on one side only (`a_only` /
  `b_only`), each with where it is referenced.
- **Pair evidence** (`pair_evidence`, `counterpart_hint`) on an undetermined pairing, and
  **alternative pairings** (`alt_pairings`) where an entry's counterpart may be another function
  than the one the diff placed it on.
- **Navigation facts** on entries: line-number and address drift, recompile-only changes,
  upstream version strings, the same entry in other diffs of the run pair, and dispatch-table
  groups.
- **Every file of both images** by path: kernel modules (`ko_changes`: section differences and the
  functions of their executable sections) and symbolic links (`symlink_changes`) besides scripts,
  config files and web assets; every changed file counts toward completing the review.
- **The other side of an unmatched function is probed**: a function there under another name
  (`counterpart_suspected`), bytes Ghidra never disassembled, a thunk or a stub-table entry — so
  "no counterpart" is said only when it holds.

Scan and hunt

- **Static `{string -> handler}` dispatch tables** are read from the stored image at hunt time:
  records of two to eight words, key first or last, each pairing graded by its evidence
  (`pairing_basis`). A handler that is a thunk or an imported function is named after its target.
- **Configuration-store getters, and a binary's own value getters, count as weak sources.** Each
  candidate records which sources its function calls (`source_names`) and how its function's
  boundary was found.
- **Launches through a runner**: a function that execs the argument vector its caller built links
  the caller to the program it starts.
- **Thin wrappers around path and file sinks** are followed one hop; the path is read at the
  positions the wrapper forwards.
- **ARM and AArch64 lazy-binding stub tables** are decoded instruction by instruction, so a call
  through a stub is named after its import. An `IRELATIVE` slot is named only when exactly one
  `STT_GNU_IFUNC` symbol matches it.
- The extraction records each thunk's target, where the image holds each imported function, and
  raw observations of the code that reads data tables (for table readers to come; nothing is
  ranked on them yet).
- Code reached only through data pointers is recovered as functions (`origin = recovered`), and
  executable bytes Ghidra never disassembled are recorded per binary.
- Each binary is extracted in its own Ghidra session, its BinExport written in that session and
  archived; `tmap diff` reads the archive instead of exporting again.

Fact tools and docs

- Thirteen fact tools whose answers could outgrow a response now page (`limit` / `offset`,
  exact totals, `next_offset`).
- `SECURITY.md`: how to report a vulnerability.

### Changed

- `get_diff_patch_view` floats a sink callee swap and a change in sink call counts, lists bucket
  S, and shows binaries present on one side only.
- A `no_real_change` or `change_inconclusive` judgment counts toward coverage only once its
  must-read subject was read whole; a partial read is counted as partial.
- Blind auditing (a second agent re-judging without seeing the first verdict) is off in this
  version; `tmap review audit` still settles disagreements.
- The default per-binary analysis budget is 600 seconds (`ghidra.headless_timeout_seconds`).
- The review skill goes into `~/.agents/skills` (and dsh's skills directory). Every `--install`
  is recorded, so `tmap init` keeps it current and `tmap uninstall` removes it.
- A dispatch-table handler that is an imported function has `callee_kind = 'import'`.
- `tmap runs` treats a Ghidra version it cannot compare as a caveat, never as "all match".
- A binary whose architecture changed is extracted again.
- Both READMEs are rewritten around a case study.

### Fixed

- x86 binaries are analysed with the System V calling convention their ELF uses. Ghidra had read
  them with Windows', under which their calls carried no arguments.
- A decompile that timed out under load is retried, very large functions get more room, work a
  busy session lost is run again, and what stays unfinished is named.
- Reference lists come out in a fixed order, so the same binary scanned twice gives the same
  lists.
- A thunk list that cannot be read makes the diff say "coverage unknown", never "no function
  there".
- `list_diffs` reads a one-sided binary's judgment against its own two runs.
- Shell risk lines name the command that actually runs; an escaped backquote no longer opens a
  command substitution.

---

这一版可以按工作单元审完整对版本 diff,读到的固件内容也多了很多。提取环节有变化，每个 run 都要完整重扫一次
(见「从 0.1.1 升级」)。

### 亮点

- **整对版本 diff 按单元审**:`start_diff_review(run_pair=...)` 把一对 run 切成工作单元，先发必读单元，覆盖度由服务端
  记账;`tmap review run <run_pair> --agent claude-code` 带着你的 agent 一个单元一次启动地审完。
- **给人看的发现交接**:`tmap review report --handoff` 和 `get_diff_handoff` 为每条真实发现写一块：记下的判断，以及
  tmap 对它的事实。
- **diff 对每处变化说得更多**:只在一侧出现的字符串、不确定配对的佐证与备选配对、行号漂移、只是重新编译的变化、上游
  版本升级，以及两边镜像里的每一个非二进制文件。
- **固件看得更全**:静态派发表、配置读取函数作为来源、经执行器函数启动的程序、经薄包装传入的路径，以及逐条解码的
  ARM / AArch64 PLT 桩表。
- **提取更稳**:每个二进制单独一个会话，它的 BinExport 归档给 `tmap diff` 用;只被数据指针指到的代码会被找回;
  Ghidra 没反汇编的字节会报出来;反编译超时会重试。
- **大结果分页**:各事实工具的大结果改为分页，不再截断。

### 从 0.1.1 升级

- 跑一次 `tmap rescan`。提取环节变了，**每个二进制都会重新反编译**,大镜像要预留较长时间。中途打断的重扫会保留已完成
  的二进制。
- 对之前 diff 过的每一对重跑 `tmap diff --before A --after B`。diff 代码变了，旧 diff 在重跑前都显示为过期。
- 再跑一次 `tmap init`:它会安装 `tmap-diff-review` agent 技能。
- 重启 MCP 客户端(或重连 `treasure-map` 服务器),加载新的工具清单。
- `analysis.db` 和 atlas 首次打开时自动补上新表和新列。这样补上的列在重扫写入之前读作"未记录"。

### 新增

diff 审阅

- **`start_diff_review(run_pair=...)`**:整对 run 切成工作单元(单个条目、callee 组——新调用同一个函数的条目放在
  一起读——以及非二进制文件),附服务端计算的报告:`coverage_statement`、必读单元和 `must_read_complete`。用
  `annotate_diff(..., unit_id=...)` 判每个成员，反复调用直到 `next_unit` 为 null。默认只发必读单元，第二层在之后
  提供。`worker` / `workers` 可把一对 run 分给多个会话，每次下发都会说明这对 run 进度如何、新会话怎么接着做。
- **`tmap review`**:`report`(摘要，或用 `--md` / `--html` 输出完整报告)、`judge`(人的判断，成为当前判断，
  agent 的判断留在历史里)、`audit`(待裁决分歧的工作表,`--emit` / `--apply`)、`run`(批处理驱动：每个单元启动一次
  你的 agent——预设 `claude-code`,实验性的 `codex` / `cursor`,或命令模板——支持 `--max-units`、`--max-minutes`、
  `--worker` / `--workers`、`--until must_read|complete` 和 `--handoff FILE`)以及 `skill`(打印或安装审阅技能)。
- **`get_diff_handoff(run_pair)`** 和 **`tmap review report --handoff`**:把这对 run 的 `changed_real` 发现写成
  标准交接，每条发现一块：判断、变化、可达形态、同形兄弟，以及两栏留给人填写(`--analysis` 可附上 agent 的文字)。
  必读集完成后才提供。
- atlas 旁边新增一份工具调用日志，服务端据此判断一个会话读过哪些材料。

diff 事实

- **`get_diff_string_delta(diff_id)`**:只在一侧出现的字符串字面量(`a_only` / `b_only`),各带引用位置。
- 未定配对上的**配对佐证**(`pair_evidence`、`counterpart_hint`),以及条目的对端可能不是 diff 放的那个函数时给出
  **备选配对**(`alt_pairings`)。
- 条目上的**导航事实**:行号与地址漂移、只是重新编译的变化、上游版本字符串、同一条目在这对 run 其他 diff 里的情况，
  以及派发表分组。
- 按路径覆盖**两边镜像的每一个文件**:除脚本、配置文件和 web 资源外，还有内核模块(`ko_changes`:段的差异和可执行段
  里的函数)和符号链接(`symlink_changes`);每个有变化的文件都计入审阅完成度。
- **未配上的函数会探测对侧**:那边是否有改了名的函数(`counterpart_suspected`)、Ghidra 没反汇编的字节、thunk 或
  桩表条目——只有确实如此时才说"没有对端"。

扫描与 hunt

- hunt 时从存储的镜像里读**静态 `{字符串 -> handler}` 派发表**:记录宽 2 到 8 个字，键在前或在后，每种配对按证据
  分级(`pairing_basis`)。handler 是 thunk 或导入函数时，按它的目标命名。
- **配置存储的读取函数，以及二进制自己的取值函数，算作弱来源。** 每个候选记录它所在函数调用了哪些来源
  (`source_names`),以及函数边界是怎么定出来的。
- **经执行器启动**:一个函数执行调用方拼好的参数向量时，把调用方连到它启动的程序。
- **路径 / 文件 sink 的薄包装**会跟进一跳，按包装转发的位置读取路径。
- **ARM 和 AArch64 的懒绑定桩表**逐条指令解码，经桩的调用按导入名命名。`IRELATIVE` 槽只在恰好对上一个
  `STT_GNU_IFUNC` 符号时才命名。
- 提取会记录每个 thunk 的目标、映像里每个导入函数的位置，以及读数据表的代码的原始观察(供后续的表读取器使用;本版
  还没有任何排序依据它)。
- 只被数据指针指到的代码会被找回成函数(`origin = recovered`),Ghidra 没反汇编的可执行字节按二进制记录。
- 每个二进制在单独的 Ghidra 会话里提取，它的 BinExport 在同一会话里写出并归档;`tmap diff` 直接读归档，不再重新导出。

事实工具与文档

- 结果可能超出单次响应的 13 个事实工具改为分页(`limit` / `offset`、精确总数、`next_offset`)。
- `SECURITY.md`:如何报告漏洞。

### 变更

- `get_diff_patch_view` 把 sink 被调函数的替换和 sink 调用次数的变化上浮，列出 S 桶，并显示只在一侧存在的二进制。
- `no_real_change` 或 `change_inconclusive` 判断只有在它的必读对象被完整读过后才计入覆盖度;只读了一部分的按部分计。
- 盲审(第二个 agent 在看不到第一个结论的情况下重判)在本版关闭;`tmap review audit` 仍可裁决分歧。
- 每个二进制的默认分析时限改为 600 秒(`ghidra.headless_timeout_seconds`)。
- 审阅技能装进 `~/.agents/skills`(以及 dsh 的技能目录)。每次 `--install` 都会记账，所以 `tmap init` 会保持它最新，
  `tmap uninstall` 会把它删掉。
- 派发表里 handler 是导入函数时，`callee_kind = 'import'`。
- `tmap runs` 遇到无法比较的 Ghidra 版本时给出提示，不再显示"全部一致"。
- 架构变了的二进制会重新提取。
- 中英文 README 都围绕一个案例重写。

### 修复

- x86 二进制按其 ELF 使用的 System V 调用约定分析。此前 Ghidra 按 Windows 调用约定读取，调用一律没有实参。
- 负载下超时的反编译会重试，特别大的函数给更多空间，忙碌会话丢掉的工作会重跑，仍未完成的会点名列出。
- 引用列表按固定顺序输出，同一个二进制扫两次得到相同的列表。
- thunk 列表读不出来时,diff 说"覆盖未知",不再说"那里没有函数"。
- `list_diffs` 按单侧二进制自己的两个 run 读它的判断。
- shell 风险行写的是实际执行的命令;转义的反引号不再被当成命令替换的开头。

## [0.1.1] - 2026-10-26

Still a developer preview. Several MCP tool parameters and result fields changed (see Changed);
an agent prompt or script written against 0.1.0 may need adjusting.

### Upgrading from 0.1.0

- Run `tmap rescan` once. A run scanned by 0.1.0 records no code stamp, so every run is offered.
  The extraction pass is the same as 0.1.0's, so no binary is decompiled again (only binaries
  whose last extraction failed are retried): the rescan rebuilds the inventory, cross-binary
  references and non-binary facts, and hunts the run again.
- Run `tmap diff --before A --after B` again for each pair you diffed. The diff code changed, so
  every stored diff reads as out of date (`source_stale`) until it is re-run.
- Restart your MCP client (or reconnect the `treasure-map` server) so it loads the new tool list.
- `analysis.db` and the atlas gain their new tables and columns automatically on first open.

### Added

- **`start_diff_review(diff_id)`**: one call that opens a diff review — the entries to read
  first, the change at the top shown inline, the diff's metadata and its non-binary files, and
  the review workflow — sized to fit one response.
- **The changed lines, inline.** A function pair's `pseudocode_delta` carries `inline_hunk`: the
  changed blocks as each side's original text writes them, with substitutions (a moved number, a
  renamed identifier) grouped one per line. The comparisons a change introduces (a variable
  checked against a constant) are listed beside it as `guards`.
- **More reasons to read a pair first**: a sink call that changes in the callee set but not at
  the matched instruction (`sink_callee_swap`); an undetermined pair that shares an address or
  real name across the two sides and reads differently (`anchored_differs`); a function that
  loses every direct caller (`callers_a` / `callers_b`, bucket E).
- **`same_shape_siblings`**: the other calls of one sink call's shape in the same binary, and
  where each landed in the diff. A judgement that names such a group is flagged for re-checking
  when the group changes.
- **Non-binary files in a diff.** `get_file_diff` compares two runs' scripts, config files,
  credentials and web assets by path (credential values and embedded secrets are never
  returned), and `annotate_diff(..., run_pair=...)` records a judgement on one file.
- **`annotate_diff_batch`**: up to 200 judgements on one diff in a single call, all or none.
  `no_real_change` now has to point at something it checked in the current view.
- **`get_data_table`** and entry words: where a function's entry address is stored as data (a
  dispatch table, a callback slot), and a reader for the table around it.
- **`get_tool_reference`**: a tool's full description, the working guide, and the parameter-name
  table.
- `get_pseudocode` says why a function has no pseudocode (`skipped_micro`, `decompile_empty`,
  `size_unknown`); a function too small to decompile comes with its disassembly inline.
- **Scripts that start a binary indirectly** are recorded as its entry evidence: through a
  function's positional parameter (`run_it svc`), a variable holding a command (`$DAEMON`,
  `$BASE/$NAME`), or a command substitution (`X=$(svc ...)`). Each recorded script line says
  where its command came from (`via`) and which line that was (`via_line`).
  `get_script_callsites` pages its results (`tmap fact script-callsites --offset`).
- **An interrupted scan keeps its finished binaries.** Each binary is stored as soon as its
  decompile finishes; running the same command again (scan, analyze or rescan) decompiles only
  the rest. An interrupted bare `--reanalyze` continues where it stopped the next time it is run.
- **`tmap rescan` and `tmap runs` judge a run by the code that produced it** (a hash of the scan
  and hunt code, plus the parsing library version and the content-affecting config), not by the
  tmap commit: an update that does not touch the scan or the hunt leaves every run current. Runs
  that need work are grouped by what it costs — a full scan, re-extraction of the binaries the
  running pass has not yet extracted, or a re-hunt with no decompile.
- `tmap diff` retries a binary whose toolchain step failed transiently once more in the same
  run, after the parallel phase, and reports it under `recovered`.

### Changed

- **MCP tool descriptions are short cards** (the first line names the required parameters); the
  full text is one `get_tool_reference` call away. What the server sends at startup drops from
  about 95,000 to 23,000 characters. **An unknown parameter name is now refused** instead of
  being silently ignored.
- `get_diff_patch_view` reads in **significance order** by default (the entries a reviewer
  should open first lead); the previous default is `sort_by="candidate_tier"`. Pages are cut to
  fit the response budget, an entry carries at most 20 candidate rows inline (the rest paged by
  `rows_offset`), `entry_id` reads one entry in full, and `detail="summary"` gives a whole
  ranking as counts.
- A change that only shifts `__FILE__` / `__LINE__` build-info numbers is moved out of the
  read-first list, but only when the two sides' callee sets and sizes are proven equal.
- Every successful diff stores its candidate baseline, so reading a diff no longer recomputes
  the overlay.
- A promoted judgement records which kind of diff row it was carried from.
- Sink arguments are read by their form (a literal, a variable, an address, a cast, a field
  read, a call), so a type name, the first word of a string or a callee name is no longer taken
  for the variable a value flows from; the safe-value downweights are stricter about aliases.
- Script lines are split the way the shell splits them, quotes respected: a quoted value with
  spaces is one word, never a command. The command text recorded for a script line no longer
  carries those quotes.
- A binary whose extraction finished, that has executable code, and from which Ghidra recovered
  no function is recorded as `no_functions`: still listed as incomplete, named on its own line,
  and not decompiled again by the same extraction pass.
- Interactive `tmap init` downloads missing tools without asking about each one and shows a
  short numbered plan; `--dry-run` still prints the full plan with URLs and checksums.
- The agent prompts printed by `tmap init` and shown in the README ask for the whole firmware
  pair, allow an inconclusive judgement, and end with a report.

### Fixed

- `tmap uninstall` no longer leaves an empty dsh patch file that stops dsh from starting.
- A transient toolchain failure in `tmap diff` no longer needs a second run.
- Downloads under 1 MB show their size in KB instead of `0 / 0 MB`.
- `tmap init` says that tab-completion takes effect in a new shell.
- `tmap uninstall` removes the backup and the emptied config it left in Cursor and Claude
  Desktop, putting back the user's original file byte for byte.
- Interrupting a scan no longer discards every binary already decompiled in it.
- A run that has one binary the current extraction pass cannot extract is no longer listed as
  needing re-extraction forever; `tmap runs`, `tmap rescan` and `tmap init` name such binaries
  instead.
- A binary cut off by Ctrl-C (or SIGTERM / SIGHUP) is no longer recorded as failed.
- A timeout or import failure logged by an earlier Ghidra run of the same binary is no longer
  read as this run's.
- `tmap rescan` no longer changes which run `tmap mcp` serves by default.
- An interrupted `tmap diff` counts as new only the binaries it actually diffed.

## [0.1.0] - 2026-10-16

First public release — a developer preview. Commands, configuration, the atlas database and MCP
tool fields may still change incompatibly between versions.

### Added

- **Firmware map (`tmap scan`).** Takes an already-extracted firmware filesystem, decompiles every
  ELF with Ghidra 11.4.3 (headless, in parallel, with a per-binary heap and timeout and one serial
  retry, at a doubled budget, for binaries that fail), and records the facts in a per-firmware `analysis.db`:
  functions with pseudocode and a compact disassembly listing, callees, cross-binary references,
  strings, imports/exports, raw data-segment bytes, and the shell scripts, config files and web
  assets around the binaries. It then marks every call that runs a shell command, copies into a
  buffer, formats a string or opens a file by path, and writes those candidates into the shared
  atlas (`~/.treasure-map/atlas.db`).
- **Candidates annotated layer by layer, with no score.** Each candidate carries a three-state
  reading (YES / NO / UNKNOWN with the reason) on where its data comes from, how much of it is
  controllable, who wrote the value, how the spot is reached, whether anything filters it, its
  impact, and whether the function was fully analyzed. The default view ranks by impact and
  sinks only candidates proven safe; an UNKNOWN never pushes a candidate down. Command, copy and
  format-string sinks carry in-function argument provenance from Ghidra's def-use data.
- **Patch diff (`tmap diff --before RUN --after RUN`).** Runs Ghidra, BinExport and BinDiff end
  to end over every binary whose content changed, and presents a function-level patch view
  grouped by what happened around each function's dangerous calls, with an address-normalized
  pseudocode comparison and flags for changed length constants. Binaries that could not be
  diffed are listed as blind spots, never counted as unchanged; a function without a
  counterpart is reported as undetermined, never as removed or added.
- **MCP server (`tmap mcp`) with 34 tools** for an AI agent: the candidate map
  (`list_candidates`, `explain_candidate`, `get_sink_provenance`), fact readers (pseudocode,
  disassembly, callees, xrefs, strings, imports/exports, data bytes, script call sites, string
  references), cross-firmware and nvram views (`cross_firmware_patterns`, `pattern_density`,
  `get_nvram_key_flow`, `get_string_keyed_edges`, `launched_by`), the diff views
  (`get_diff_patch_view`, `get_diff_deltas`, `get_diff_sink_overlay`, `list_diff_blindspots`,
  ...), and an annotation layer (`annotate`, `annotate_diff`, `promote`, `list_overlays`,
  `clear_overlay`) that records the agent's judgements without changing the facts. Every result
  carries an anchor (binary + function + address) and the lineage of the scan that answered.
  A scan made by different extraction or hunt code than the one answering is refused, with the
  command that refreshes it.
- **Command-line readers** for a person cross-checking the agent: `tmap runs`, `tmap triage RUN`,
  `tmap fact` (pseudocode, disassembly, callees, xrefs, script call sites), `tmap atlas-view`
  (density, ledger), and `tmap exploit` for the private ledger of verified findings.
- **Install and setup.** `install.sh` installs `tmap` (PyPI `tmap-agents`) with a uv-managed
  Python 3.11 and runs `tmap init`, which reuses or downloads the toolchain (JDK 21, Ghidra
  11.4.3, BinExport, BinDiff 8) from pinned URLs checked by size and sha256, and registers the
  MCP server with Claude Code, Codex, Cursor, Claude Desktop or dsh. `tmap doctor` re-checks the
  setup, `tmap update` upgrades a uv-managed install, and `tmap uninstall` removes tmap's own
  files (`--purge-data` also deletes scans and the atlas after a typed confirmation).

### Known limitations

- Reachability is graded one function at a time. It is not a taint-propagation engine and never
  claims a path is unreachable; most candidates read UNKNOWN on that layer.
- Path and file sinks are detected and ranked, but their controllability comes from a text-level
  reading of the pseudocode, and is marked as such.
- The disassembly listing is only present for firmware scanned by this version; an older scan
  answers `available: false` until it is rescanned.
- Supported platforms are Linux x86_64 (including WSL2) and macOS on Apple Silicon. macOS on
  Intel runs the same toolchain but has not been acceptance-tested; Linux arm64 and native
  Windows are not supported.
- Licensed under the Apache License 2.0.
