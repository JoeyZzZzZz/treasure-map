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

| 你需要自备 | 版本 | 用途 |
|---|---|---|
| **Ghidra** | 11.4.3 | 反编译每个二进制(headless 模式) |
| **JDK** | 21 | Ghidra 11.4.3 要求——JDK 11/17 会让它启动失败 |

Ghidra 和 JDK 由你自己安装;下面的安装步骤会帮你装好 Treasure Map 和对应的 Python。**无需任何 API
key。**(一个开箱即用、把一切都打包好的 Docker 镜像正在计划中。)

Treasure Map 是一个命令行工具(`tmap`),内置一个面向 AI 的 MCP server。它**支持 macOS 和 Linux**;
Windows 上走 WSL。

**输入 = 一个已经解压好的固件文件系统。** 解包固件镜像不在 Treasure Map 的范围内——用你惯用的任意
解包工具,然后把 Treasure Map 指向解出来的目录即可。

Ghidra 11.4.3 是钉死、经过测试的工具链(实验性的 `diff` 阶段也要求它);`scan` 本身对任意 Ghidra
11.x 都能跑,但钉死版本是为了结果可复现。

---

## 安装

**1. 安装 [uv](https://docs.astral.sh/uv/)**(单个二进制,同时帮你管理对应的 Python):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # macOS / Linux
```

**2. 安装 JDK 21**——用 `java -version` 确认(必须报告 21):

```bash
# Debian/Ubuntu:  sudo apt install -y openjdk-21-jdk
# macOS:          brew install openjdk@21
# 其他:           Eclipse Temurin (https://adoptium.net)
```

**3. 安装 Ghidra 11.4.3**——下载并解压即可,无需安装程序、无需管理员权限:

```bash
curl -L -o ghidra.zip \
  https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.3_build/ghidra_11.4.3_PUBLIC_20251203.zip
unzip ghidra.zip -d ~/ghidra && rm ghidra.zip
export GHIDRA_HOME=~/ghidra/ghidra_11.4.3_PUBLIC   # 指向包含 support/analyzeHeadless 的那个目录
```

**4. 安装 Treasure Map:**

```bash
uv tool install --python 3.11 "git+https://github.com/JoeyZzZzZz/treasure-map.git"
```

**5. 一次性配置:**

```bash
tmap init
```

`init` 会写入 `~/.treasure-map/config.yaml`,从 `GHIDRA_HOME` 检测 Ghidra(或问你一次),并跑一遍
预检。把它标 `❌` 的项修好,再重跑。没有 `❌` 时,你就准备好了。

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

Treasure Map 自带一个 MCP(Model Context Protocol)server。**只需注册一次**——不用填路径、不用为每
个固件单独配置。这个 server 绑定你的整个 `atlas`(你扫过的一切汇成的知识库);**由 agent 按 `run_id`
自己挑要处理哪个固件**,新跑的 `tmap scan` 无需重新配置即可用。

| Agent | 注册一次 |
|---|---|
| **Claude Code** | `claude mcp add -s user treasure-map -- tmap mcp` |
| **Codex (OpenAI)** | `codex mcp add treasure-map -- tmap mcp` |
| **Cursor / Windsurf / Gemini CLI / 其他 JSON 客户端** | 把下面这段加进客户端的 MCP 配置文件 |

```json
{
  "mcpServers": {
    "treasure-map": {
      "command": "tmap",
      "args": ["mcp"]
    }
  }
}
```

配置文件位置:Cursor `~/.cursor/mcp.json`、Windsurf `~/.codeium/windsurf/mcp_config.json`、Gemini
CLI `~/.gemini/settings.json`;VS Code——`code --add-mcp '{"name":"treasure-map","command":"tmap","args":["mcp"]}'`。

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

- **`tmap: command not found`**——工具的 bin 目录不在 PATH 上。跑 `uv tool update-shell`,然后开一个
  新 shell。
- **`Ghidra : not found` / `not auto-detected`**——在 `~/.treasure-map/config.yaml` 里把
  `ghidra.local.home` 设为你的 Ghidra 安装根目录;确认 `<root>/support/analyzeHeadless` 存在。
  (WSL:装 **Linux** 版,并用 Linux 路径,而不是 `/mnt/c/...`。)
- **`java: not on PATH`**——确保 `java -version` 报告 **21**(装了多个的话用 `update-alternatives
  --config java`)。

任何修复之后,重跑 `tmap init` 再检一遍。

---

## 卸载

```bash
uv tool uninstall treasure-map
```

这会**保留 `~/.treasure-map/`**——你的配置,尤其是 **`atlas.db`**,那个跨固件的知识库会随每次运行
累积、永不重建。重新安装会复用其中全部内容。要连 `atlas.db` 一起彻底清除:`rm -rf ~/.treasure-map`
(不可恢复——不推荐)。

---

## 许可证

[Apache-2.0](LICENSE)。
