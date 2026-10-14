# Treasure Map

[English](README.md) | [中文](README.zh.md)

**Treasure Map 是一个面向 AI 驱动的固件漏洞研究的侦察(reconnaissance)工具。** 把它指向一台 IoT
设备固件解包出来的文件系统,它会找出编译代码里每一处"对数据做危险操作"的地方:执行 shell 命令、往
内存缓冲区拷贝、格式化日志字符串、或按路径打开文件。对每一处,它诚实地记下自己能确定什么——这数据
从哪来、这个点怎么被到达——以及同样重要的、自己**判不出**什么。然后把这张地图交给你的 AI 编程
agent(Claude Code、Cursor、Codex)去核查,每条线索都可精确溯回到具体的二进制、函数和地址。

就像它名字里的那张藏宝图,它告诉你去哪儿挖、并诚实标注地形——哪里有把握、哪里没有——但从不说"宝藏
就在这儿"。哪条线索是真漏洞、能不能被利用,那是你的 AI 的活。**事实是工具的活,推理是模型的活。**

你只手动跑一条命令来建出这张地图;之后的活由你的 AI 通过 Treasure Map 内置的 MCP server 完成。

---

## 为什么是"事实底座",而不是又一个扫描器

扫描器给你一堆发现和一个严重度分数——一个你只能选择相信、或自己回头核的判决。Treasure Map 给你的
是事实。它从不判断哪个候选是真漏洞、哪个可利用;它做的是 AI 自己做不了的那一半——在一整个固件的规
模上、可复现地,把每一条危险线索都摊出来,并诚实标注它知道什么、不知道什么、暂时还判不出什么。今天
的 agent 读懂并推理单个函数已经很好;它做不到的是把一整个根文件系统(乃至一支跨版本的固件舰队)
**完整、且两次一致地**扫一遍。那道缺口,才是工具该干的活。

- **三态诚实。** 每个事实要么 YES、要么 NO、要么一个显式的 UNKNOWN——绝不把"判不出"伪装成一个笃
  定的答案。即便在函数内没找到输入源,危险 sink 也照样列出(受控值可能是从调用方传进来的),所以
  工具绝不会把一条自己没能完整追通的线索悄悄丢掉。

- **按信号排序,绝不按判决排序。** 候选被排序,让信号更强的线索浮到前面,但工具从不把任何一条判定
  为"是"或"否"。只有**已证明安全**的事实才能把一个候选往下压;一个 UNKNOWN 永远压不下去。按任意维度
  重排只是换一个视角看这份地图——它不会缩减候选。可达性是**逐函数**分级的:这**不是**污点传播引擎,
  它也从不宣称某条路径"不可达"。

- **供线索,不下结论。** 它提供事实、调用链、可达性证据——绝不产 payload、PoC 或"这个可利用"。一个
  候选是待核查的线索,不是已确认的漏洞。

- **判断会沉淀。** 你的 AI 自己的判断,落在只读事实之上的一个标注层里,所以一次跨多轮的审计能接着上
  次继续,而不必从头再来——一旦底下的事实发生变化,对应的判断会被标记为需要复核。

agent 越强,事实底座越有用:工具给 AI 喂它自己产不出来的、诚实且完整的输入,让 AI 在其之上推得更深。

---

## 环境要求

`tmap init` 会替你装好工具链——如果你已经装了、而且核验通过,就直接复用:

| 工具 | 版本 | 用途 |
|---|---|---|
| **JDK** | 21(要 JDK,不是 JRE) | 运行 Ghidra 11.4.3——JDK 11/17 会让它启动失败 |
| **Ghidra** | 11.4.3 | 反编译每个二进制(headless 模式) |
| **BinExport** | 对应 Ghidra 11.4.3 | 为 `tmap diff` 导出二进制 |
| **BinDiff** | 8 | 为 `tmap diff` 在两个固件版本之间匹配函数 |

下载地址是钉死的;解包之前先按钉死的大小和 sha256 核验。下载内容放在 `~/.treasure-map/toolchain/`。
**无需任何 API key。**

| 平台 | 状态 |
|---|---|
| Linux x86_64(含 WSL2) | 支持 |
| Apple Silicon 上的 macOS | 支持 |
| Intel 上的 macOS | 跑同一套工具链;未经验收 |
| Linux arm64、原生 Windows | 不支持(没有 Ghidra 反编译器 / BinDiff 的对应构建);Windows 上用 WSL2 |

**输入 = 一个已经解压好的固件文件系统。** 解包固件镜像不在 Treasure Map 的范围内——用你惯用的任意
解包工具,然后把 Treasure Map 指向解出来的目录即可。

---

## 安装

```bash
curl -LsSf https://github.com/JoeyZzZzZz/treasure-map/releases/latest/download/install.sh | sh
```

脚本会先打印计划;没有 [uv](https://docs.astral.sh/uv/) 就装上(不改你的 shell rc);用 uv 管理的
Python 3.11 装好 `tmap`(PyPI 包名 `tmap-agents`);然后进入 `tmap init`。`install.sh --dry-run`
只显示计划、什么都不改。已经有 uv 的话,`uv tool install --python 3.11 tmap-agents` 再 `tmap init`
效果相同。

`tmap init` 会:

1. **查找**已有的 JDK 21、Ghidra 11.4.3、BinExport、BinDiff 8(config、`GHIDRA_HOME`、`JAVA_HOME`、
   PATH、常见安装位置),逐个做文件级核验;
2. 对缺的组件,**问你**路径,或提供钉死版本的下载;
3. **列出你的 agent**(Claude Code、Codex、Cursor、Claude Desktop、dsh),本机装了的已默认勾选——
   空格取消,回车确认;
4. **展示计划**(每个下载的 URL、大小、sha256;每个要改的文件),问 `Apply N changes? [Y/n]`;
5. **执行**,然后跑 **doctor**,并打印两大功能的用法。

随时可以重跑:已是最新的环境会报告 "everything current, nothing to do"。常用参数:`--dry-run`(只看
计划)、`--yes`(不提问、包含下载;只注册用 `--client` 点名的 agent)、`--non-interactive`(不提问、
不下载)、`--ghidra / --java-home / --bindiff PATH`(就用这个)、`--offline DIR` / `--mirror URL`
(从别处取归档,校验和不变)。`tmap doctor` 重跑检查、不写任何文件。

> Ghidra 会记住它上次用的 JDK(其设置目录里的 `java_home.save`)。tmap 运行 Ghidra 11.4.3 时会把
> tmap 所用的 JDK 记进去;你自己不设 `JAVA_HOME` 启动的 Ghidra 11.4.3 之后可能会选用这个 JDK。

---

## 开始用

把 Treasure Map 指向你解压好的固件根目录,跑一条命令:

```bash
tmap scan ./firmware.extracted -w my-firmware
```

`-w` 是你给这个固件的 workspace 起的名字——任意标签都行。它会反编译每个二进制、建出这张事实地图——
慢的那步(每个二进制一遍 Ghidra),会显示进度。用**同一个** `-w` 重跑是断点续跑安全的:它会从上次
的 Ghidra 检查点继续,跳过已经做完的二进制。换一个**不同的** `-w`,就会得到一个独立的 workspace,
于是你可以把多个固件并排放着,各自留着各自的结果。

这是你唯一手动跑的命令。之后的一切——读排序后的线索、跨固件追查、记录判断——都由你的 AI agent 经
MCP server 完成 ↓

---

## 接入你的 AI agent

Treasure Map 自带一个 MCP(Model Context Protocol)server,`tmap init` 会把它注册进你选中的 agent。
这个 server 绑定你的整个 `atlas`(你扫过的一切汇成的知识库);**由 agent 按 `run_id` 自己挑要处理
哪个固件**,新跑的 `tmap scan` 无需重新配置即可用。注册后重启一下 agent。

手动注册时,命令一律是 `<tmap 的绝对路径> mcp`(`command -v tmap`):

| Agent | 注册 |
|---|---|
| **Claude Code** | `claude mcp add -s user treasure-map -- "$(command -v tmap)" mcp` |
| **Codex (OpenAI)** | `codex mcp add treasure-map -- "$(command -v tmap)" mcp` |
| **Cursor / Claude Desktop / 其他 JSON 客户端** | 把下面这段加进客户端的 MCP 配置文件 |
| **dsh** | `tmap init --client dsh` 会把条目追加到 `~/.dsh/cordis.patch.yml` |

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

配置文件位置:Cursor `~/.cursor/mcp.json`、Claude Desktop `~/Library/Application Support/Claude/
claude_desktop_config.json`(macOS)、Windsurf `~/.codeium/windsurf/mcp_config.json`、Gemini CLI
`~/.gemini/settings.json`。Claude Code 请用 `-s user`:同名的项目级条目会在那个项目里遮住它
(`tmap doctor` 会把这类条目指出来)。

然后就用大白话跟你的 agent 说——工具不用你驱动,由它来驱动:

> 用 treasure-map 审计这个固件。从排序列表顶部往下逐条看——打开线索的伪代码、往上游追、自己判断。
> 它们是待核查的线索,不是确认的漏洞。

底层上,agent 在这些 MCP 事实工具上跑一个简单的循环:**召回**排序后的候选(`list_candidates`)、为
一条线索**取事实**(`explain_candidate`、`get_pseudocode`、`get_callees`、`get_xrefs`、`get_strings`、
`get_sink_provenance` 等),然后**判断**——把判定记进只读事实之上的标注层(`annotate`)。每个事实工
具都按 `run_id` 或某个候选的 `evidence_ref` 路由,所以一个 server 就能服务你扫过的每一个固件。

---

## 状态

早期开发中——API 和行为可能变动。

- **稳定:** `scan` 流水线(analyze → hunt → triage)、面向 AI 的 MCP 事实层、以及标注层。sink 覆盖:
  命令执行、缓冲区拷贝、格式化字符串注入类 sink 带函数内实参来源(provenance);**路径/文件类 sink
  目前覆盖到检测与排序**(尚无函数内实参 provenance——它们的可控性来自一次文本层面的源读取,并诚实
  标注)。
- **实验性:** `diff`(跨构建补丁对比)——正在积极开发;**不影响** `scan`。

---

## 预期用途与法律

**目的。** Treasure Map 服务于固件的防御性安全审计与漏洞研究。它产出候选发现与分析线索;按设计,它
**不**生成概念验证利用、payload、shellcode 或其他可直接武器化的产物。

**合法使用由你自己负责。** 只分析你合法持有的固件——你自己拥有的设备,或厂商真正公开发布、且**未**
绕过任何登录/付费墙/访问控制而获得的固件。即便是合法获得的固件,也可能带有关于逆向工程的许可、服务
条款或合同限制;审阅这些是你的责任。

**发现是候选,不是判决。** 输出需要独立的人工核查,并非已确认的漏洞。

**不提供任何担保。** 本工具按"原样"提供。你如何使用、以及确保你的行为在你所在司法辖区内合法,完全
由你自己负责。如有疑问,在着手前请咨询合格的法律顾问。

---

## 排障

先跑 `tmap doctor`:每项检查给出 ✅、⚠(可用,但值得注意)、`·`(仅供参考)、❌ 或 `?`(无法确定——
永远不显示为 ✅);有任何 ❌ 或 `?` 时以非 0 退出。

- **`tmap: command not found`**——工具的 bin 目录不在 PATH 上。跑 `uv tool update-shell`,然后开一个
  新 shell。
- **`ghidra` / `java` / `bindiff` ❌**——重跑 `tmap init`,它会提供钉死版本的下载;或者传
  `--ghidra / --java-home / --bindiff PATH`。(WSL:全部放在 Linux 一侧,不要放在 `/mnt/c/...` 下。)
- **`binexport` ❌ "two copies"**——Ghidra 会从自己的 `Ghidra/Extensions` 和它的用户设置目录两处加载
  扩展;删掉其中一份。

---

## 卸载

```bash
tmap uninstall              # agent 注册 + tmap 下载的工具链
uv tool uninstall tmap-agents
```

`tmap uninstall` 只删除 `tmap init` 记录过自己安装的东西——绝不碰你自己装的 JDK、Ghidra 或 BinDiff——
并且**保留 `~/.treasure-map/`**:你的配置,尤其是 **`atlas.db`**,那个跨固件的知识库会随每次运行累积、
永不重建。重新安装会复用其中全部内容。`tmap uninstall --purge-data` 会在你输入确认短语之后连 atlas 和
工作区一起删除(不可恢复——不推荐)。

---

## 许可证

[Apache-2.0](LICENSE)。
