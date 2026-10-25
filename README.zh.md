# Treasure Map（藏宝图）

[English](README.md) | [中文](README.zh.md)

**给 AI agent 的固件藏宝图：地图标出地形，宝藏由你的 agent 去挖。**

Treasure Map 把解包后的固件文件系统变成一组事实，通过内置的 MCP 服务器交给你的编程 agent（Claude
Code、Codex、Cursor 等）：它认得的每一处危险调用，流到那里的数据从哪来，以及同样重要的——哪些它没能查清。每条事实都指向具体的二进制、函数和地址。它不带自己的 agent，也不运行任何模型；哪条线索是真漏洞，由你的 agent 来判断。**事实归工具，推理归模型。**

它做两件事：

- **给一个固件画地图。** 编译后的代码里每一处执行 shell 命令、拷贝内存缓冲区、格式化字符串、按路径打开文件的地方，都标明哪些已经查清、哪些还不知道、为什么。你的 agent 自己挑要看的视图，读代码，记下结论。
- **对比两个版本。** 两个版本之间所有改动过的函数，按危险调用附近发生了什么分好类。agent 不用在几千个函数里大海捞针，只需审改过的那几个：这是不是一次安全修补，它修掉的是旧版本里的哪个 1day？修得够不够，同样的调用是不是还留在别处？新加的检查能不能被绕过？

> **开发者预览版。** 命令、配置文件、atlas 数据库和 MCP 工具的字段，在版本之间可能出现不兼容的变化。升级后请看 [升级](#升级)。

---

## 快速开始

**1. 安装。** 一条命令装好 `tmap`，随后自动运行 `tmap init`：它会配置工具链（JDK 21、Ghidra
11.4.3、BinExport、BinDiff 8，已经装好的会直接复用），并把 MCP 服务器注册到你选择的 agent。不需要任何
API key。完成后重启你的 agent。

```bash
curl -LsSf https://github.com/JoeyZzZzZz/treasure-map/releases/latest/download/install.sh | sh
```

**2. 给一个固件画地图。** 输入是**已经解包**的文件系统，请先用你习惯的工具解包固件镜像。

```bash
tmap scan ./firmware.extracted -w my-fw
```

然后对你的 agent 说（下面是 `tmap init` 打印的提示词，用中文说同样的意思也可以）：

```text
Audit firmware my-fw using treasure-map.
Choose for yourself which views of its candidate map to review
(by sink, by data source, or by any other layer) and find the issues in them:
open a lead's pseudocode, trace where its input comes from, and judge it yourself.
The candidates are leads to verify, not confirmed bugs.
Record each conclusion with annotate so the next session starts from it.
```

**3. 或者对比两个版本。**

```bash
tmap scan ./fw_v1.extracted -w fw-v1
tmap scan ./fw_v2.extracted -w fw-v2
tmap diff --before fw-v1 --after fw-v2
```

```text
Review the diff fw-v1 → fw-v2 using treasure-map.
Start from start_diff_review:
for each changed function, compare the pseudocode of both versions
and decide whether the change does something real, such as a new check or a changed bound.
Record each judgement with annotate_diff.
```

需要你手动运行的就这些。`scan` 是最慢的一步：每个二进制跑一遍 Ghidra，会显示进度。用同一个 `-w` 重新运行会从中断处继续；换一个 `-w` 就能并排保存另一个固件。你扫过、比过的所有结果都积累在同一个
**atlas**（`~/.treasure-map/atlas.db`）里，由 agent 自己选择看哪个固件、哪次对比，每次扫描后都不用重新配置。

---

## agent 能拿到什么

### 固件地图

每个候选是地图上的一个点，带着几张平等的图层：数据从哪来，攻击者能控制多少，这个值是谁写的，怎么走到这里，路上有没有过滤，这个函数有没有分析完整。每张图层只有三种状态：**是**、**否**，或者明确的
**未知**；"未知"会写明缺什么、为什么没查到。

没有分数。默认视图把影响最大、又没有任何事实证明安全的调用排在最前面；agent 可以按任意图层重新排序或筛选。重新排序只改变顺序，不改变候选集合。无论在哪个视图里，只有**已证明安全**的事实能让候选下沉，"未知"永远不会。

命令执行、内存拷贝、格式化字符串这三类调用，带有函数内的参数来源分析。路径和文件类调用目前只做检测和排序，它们的可控性来自文本层面的读取，并且会如实标明。

### 补丁对比

`tmap diff` 会并行对比所有内容有变化的二进制，从 Ghidra、BinExport 到 BinDiff 全程自动完成，你不用碰任何中间文件。（`--binary NAME` 只对比指定的一个。）

- **函数级补丁视图。** 每对改动过的函数一条，按危险调用附近发生了什么分组：调用的目标换了，危险调用还在原处，或者无法判定。可选的排序会把最可能重要的条目放在前面。
- **相似度看不到的改动。** BinDiff 的相似度会忽略常量：一个函数可能显示 `similarity=1.0`，而缓冲区长度已经从 `0x40` 改成了 `0x3f`。tmap 额外做了地址归一化后的伪代码比较（真正相同，还是只是相似），并标出拷贝或格式化调用处被改动的长度常量。
- **盲区明说，不藏。** 没能对比的二进制会单独列出，绝不计为"没变"。找不到对应函数的，标为"未定"
  （可能被内联或挪走了），绝不报成"删除"或"新增"。
- **判断留得下来。** agent 在每个条目上记录这处改动有没有实际作用，并可以把判断带到固件地图里对应的候选上。

如果已存的扫描或对比结果是旧版 tmap 生成的，`tmap diff` 会先把它们更新到最新，并在开始前说明需要做哪些工作。

---

## 为什么只给事实，不给结论

扫描器给你的是发现和严重程度评分，也就是一个结论，你要么信，要么自己再查一遍。现在的 agent 已经很擅长读懂并推理一个函数；它做不到的是把整个根文件系统、或者两个版本之间所有改动过的二进制，每次都按同样的方式扫一遍，并且说清自己哪里没看到。这一半由 Treasure Map 来做。

- **"未知"绝不等于"安全"。** 没能确认的事实就保持"未知"；对比失败的二进制绝不显示为"没变"。
- **给线索，不给结论。** 候选是待验证的线索，不是确认的漏洞；改动过的函数是待审的改动，不是确认的修复。可达性按单个函数分级——这**不是**污点传播引擎，也从不声称某条路径不可达。
- **判断会积累。** agent 的结论存放在只读事实之上的标注层里，多次会话的审计可以从上次停下的地方继续，换模型、换 agent 都一样。底层事实一旦变化，压在上面的判断会被重新标为待复核。

---

## 安装细节

`tmap init` 会替你安装工具链；你已有的版本只要通过检查，就直接复用：

| 工具 | 版本 | 用途 |
|---|---|---|
| **JDK** | 21（必须是 JDK，不是 JRE） | 运行 Ghidra（用 JDK 11/17 时 Ghidra 11.4.3 无法启动） |
| **Ghidra** | 11.4.3 | 无界面反编译每个二进制 |
| **BinExport** | 对应 Ghidra 11.4.3 | 为 `tmap diff` 导出二进制 |
| **BinDiff** | 8 | 在两个版本之间匹配函数 |

所有下载都来自固定的 URL，解压前会校验固定的文件大小和 sha256，存放在 `~/.treasure-map/toolchain/`。

| 平台 | 状态 |
|---|---|
| Linux x86_64（含 WSL2） | 支持 |
| Apple Silicon 的 macOS | 支持 |
| Intel 的 macOS | 使用同一套工具链，未做验收测试 |
| Linux arm64、原生 Windows | 不支持（没有 Ghidra 反编译器 / BinDiff 的构建）；Windows 请用 WSL2 |

`tmap init` 的步骤：

1. **查找**已有的 JDK 21、Ghidra 11.4.3、BinExport 和 BinDiff 8（配置文件、`GHIDRA_HOME`、
   `JAVA_HOME`、PATH、常见安装位置），并逐个在文件层面检查；
2. 缺少的部分，**询问**路径，或提供固定版本的下载；
3. **列出你的 agent**（Claude Code、Codex、Cursor、Claude Desktop、dsh），本机已安装的默认勾选——空格取消勾选，回车确认；
4. **展示计划**（每个下载的 URL、大小和 sha256，以及每个将要修改的文件），并询问
   `Apply N changes? [Y/n]`；
5. **执行**计划，运行 **doctor** 检查，并打印[快速开始](#快速开始)里的那两段提示词。

随时可以再运行一次；配置已是最新时，它会报告 "everything current, nothing to do"。

<details>
<summary>参数和其他安装方式</summary>

- `install.sh --dry-run` 只打印计划，不做任何改动。脚本会在缺少 [uv](https://docs.astral.sh/uv/)
  时安装它（不修改你的 shell rc），然后用 uv 管理的 Python 3.11 安装 `tmap`（PyPI 包名 `tmap-agents`）。
- 已经有 uv：`uv tool install --python 3.11 tmap-agents`，然后运行 `tmap init`。
- `tmap init` 的参数：`--dry-run`（只看计划）、`--yes`（不提问，包括下载；只注册 `--client` 指定的
  agent）、`--non-interactive`（不提问，不下载）、`--ghidra / --java-home / --bindiff PATH`（指定使用某个路径）、`--offline DIR` / `--mirror URL`（从其他位置获取安装包，校验和不变）。
- `tmap doctor` 重新运行检查，不写入任何内容。

</details>

---

## 连接你的 agent

`tmap init` 会替你注册 MCP 服务器，注册后重启 agent 即可。

### 手动注册

命令始终是 `<tmap 的绝对路径> mcp`（`command -v tmap` 可以打印路径）。

| Agent | 注册方式 |
|---|---|
| **Claude Code** | `claude mcp add -s user treasure-map -- "$(command -v tmap)" mcp` |
| **Codex** | `codex mcp add treasure-map -- "$(command -v tmap)" mcp` |
| **Cursor / Claude Desktop / 其他 JSON 配置的客户端** | 把下面这段加到客户端的 MCP 配置文件 |
| **dsh** | `tmap init --client dsh` 会把条目写进 `$DSH_HOME/cordis.patch.yml`（默认 `~/.dsh`），所有 profile 都会读取这一层 |

```json
{
  "mcpServers": {
    "treasure-map": {
      "command": "/absolute/path/to/tmap",
      "args": ["mcp"]
    }
  }
}
```

配置文件位置：Cursor `~/.cursor/mcp.json`；Claude Desktop
`~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）；Windsurf
`~/.codeium/windsurf/mcp_config.json`；Gemini CLI `~/.gemini/settings.json`。Claude Code 请用
`-s user`：项目内同名的本地条目会在该项目里覆盖它（`tmap doctor` 会指出这类条目）。

各参数名的含义、以及它们在不同工具之间的差别：`get_tool_reference(name="parameters")`。

---

## 升级

```bash
tmap update                                 # 装上最新版 tmap
tmap rescan                                 # 重新扫描旧版 tmap 生成的所有 run
tmap diff --before fw-v1 --after fw-v2      # 重新运行已过期的对比
```

`tmap update` 会到 PyPI 查询最新版本，展示计划并询问一次（`--check` 只报告不安装，`--yes` 跳过询问）。它会替换已安装的版本；如果 PATH 上还有别的 `tmap` 会遮住新版本，会把它们指出来；最后自动启动新版本的 `tmap init`，你不用自己输入。这次 init 也会告诉你有多少个
run 早于新版本。旧版 tmap 或其他工具链生成的对比，会重新计算一次。

不带参数时，`tmap rescan` 会重新扫描所有由旧版 tmap 生成的 run。只想重扫某一个固件，就写上它的 run 名：默认就是扫描时用的 `-w` 名字（除非你另外设置了 `--run-id`），例如 `tmap rescan fw-v1`。加上 `--dry-run`
会列出将要重扫哪些、为什么，但不实际运行。

`tmap update` 适用于一键安装脚本装好的版本（`uv tool`）。如果是用其他方式安装的，请用同样的方式升级。

---

## 故障排查

先运行 `tmap doctor`。每项检查会显示 ✅、⚠（能用，但值得注意）、`·`（提示信息）、❌，或 `?`（无法判定——绝不会显示成 ✅）；出现任何 ❌ 或 `?` 时，退出码不为零。

- **`tmap: command not found`**：工具的 bin 目录不在 PATH 里。运行 `uv tool update-shell`，然后打开一个新的 shell。
- **`ghidra` / `java` / `bindiff` ❌**：再运行一次 `tmap init` 获取固定版本的下载，或者传入
  `--ghidra / --java-home / --bindiff PATH`。在 WSL 上，所有东西都要放在 Linux 一侧，不要放在
  `/mnt/c/...` 下。
- **`binexport` ❌ "two copies"**：Ghidra 会同时从自己的 `Ghidra/Extensions` 和用户设置目录加载扩展；删掉其中一份即可。
- **某个二进制没出现在对比结果里**：让 agent 调用 `list_diff_blindspots`，它会列出每个没能分析的二进制及原因。修好工具链问题后，`tmap diff … --force-retry` 会重新尝试这些二进制。
- **你自己启动的 Ghidra 11.4.3 用了意料之外的 JDK**：Ghidra 会记住上次运行时用的 JDK（设置目录里的
  `java_home.save`），而 tmap 运行时会把它使用的 JDK 记在那里。自己启动 Ghidra 时请设置 `JAVA_HOME`。

---

## 卸载

```bash
tmap uninstall
```

它会先展示计划并询问一次，然后从每个 agent 中移除 treasure-map 条目，删除 `tmap init` 下载的工具链（绝不会删除你自己安装的 JDK、Ghidra 或 BinDiff），并询问是否卸载程序本身。

**你的数据会保留：** `~/.treasure-map/config.yaml`、`.env`、**atlas** 和各个工作区，重新安装后全部可以继续使用。
`tmap uninstall --purge-data` 会把它们一并删除，需要你输入确认短语（不可恢复），但只删能证明属于 tmap 的：
atlas、含 tmap `analysis.db` 的工作区目录里扫描写下的文件，以及 `tmap init` 写的 `config.yaml` / `.env`。
工作区根目录本身不删（它是 `~/.treasure-map` 里的默认目录且已经空了时除外）；根目录是你的家目录或更上层时一个都不删。
其他东西——你自己写的文件，不论在工作区里还是旁边——都会保留并列出。

<details>
<summary>细节</summary>

- 名为 treasure-map、但运行的不是 tmap 的 agent 条目不会被动，dsh profile 自己文件里的条目也不会被动。
- 如果程序是用 `uv tool` 安装的，会用 `uv tool uninstall tmap-agents` 卸载；用其他方式安装的，
  `tmap uninstall` 会提示你用同样的方式卸载。
- `--dry-run` 只打印计划，不做任何改动；`--yes` 跳过提问，但不会跳过确认短语。

</details>

---

## 用途与法律声明

**用途。** Treasure Map 用于固件的防御性安全审计和漏洞研究。它产出的是分析线索；按设计，它**不会**生成漏洞利用 PoC、payload、shellcode 或其他可直接武器化的输出。

**合法使用由你自己负责。** 只分析你合法持有的固件：你自己拥有的设备，或由厂商真正公开发布、且获取时
**没有**绕过任何登录、付费墙或访问控制的固件。即使是合法获取的固件，也可能受许可证、服务条款或合同中关于逆向工程的限制约束，你需要自行确认。

**结果是候选，不是结论。** 输出需要独立的人工验证，不代表确认的漏洞。

**无担保。** 本工具按"原样"提供。你对自己的使用方式、以及你的活动在所在司法辖区是否合法负全部责任。如有疑问，请先咨询合格的法律顾问。

---

## 参与贡献

欢迎提交 issue 和 pull request，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

[Apache-2.0](LICENSE)。
