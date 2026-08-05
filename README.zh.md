# Treasure Map（藏宝图）

[English](README.md) | [中文](README.zh.md)

Treasure Map 把解压后的 IoT 固件，变成一张你的 AI 能在上面推理的、诚实且可复现的**事实底图**——由模型来做漏洞推理，由工具来保证：喂给模型的输入是完整的、确定性的、不是模型自己臆造出来的。

把它指向一个已解压的固件文件系统，它会反编译每一个二进制、定位危险的 sink 调用点、记录每个 sink 实参的值在函数内来自哪里、并给每个候选分级可达性——然后把一份**排好序、带证据锚点的候选清单**交给你的 AI 助手（Claude Code、Cursor、Codex 等），每条线索都可追溯到具体的二进制、函数和地址。事实是工具的活，推理是模型的活。Treasure Map 把自己那半做到极致，好让你的 AI 把它那半发挥到最好。

**它凭什么是"底图"，而不是又一个扫描器：**

- **三态诚实。** 每条事实要么 YES、要么 NO、要么明确标 UNKNOWN——它绝不把"说不准"粉饰成一个自信的答案。哪怕函数内部没找到输入源，一个危险 sink 也照样列出来（受控的值可能从调用方传进来）；已知的低产形态会沉到清单底部，但**从不删除**。
- **供线索，不下结论。** 它给的是事实、调用链、可达性证据——绝不给 payload、PoC 或"这个可利用"。判断和验证，交给你或你的 AI。
- **判断会沉淀。** 你的 AI 自己的结论，会落在只读事实之上的一张**标注层**里，于是跨会话的审计能接着上次继续、而不是每次从零开始——而且一旦它所依据的事实变了，那条判断会被自动标记为"需复审"。

命令行：`tmap`，内置面向 AI 的 MCP server。**支持 macOS 和 Linux**（Windows 上请用 WSL）。

---

## 依赖

| 你需要自备 | 版本 | 用途 |
|---|---|---|
| **Ghidra** | 11.4.3 | 反编译每个二进制（headless 模式） |
| **JDK** | 21 | Ghidra 11.4.3 要求——JDK 11/17 会让它启动失败 |

Ghidra 和 JDK 需你自己装；下面的安装步骤会帮你装好 Treasure Map 和它需要的 Python。**无需任何 API key。**（一个开箱即用、把一切都打包好的 Docker 镜像正在计划中。）

**输入 = 一个已经解压好的固件文件系统。** 解包固件镜像不在 Treasure Map 的范围内——用你惯用的任何解包工具，然后把 Treasure Map 指向解出来的那个目录即可。

---

## 安装

**1. 安装 [uv](https://docs.astral.sh/uv/)**（一个单文件二进制，同时帮你管好对应的 Python）：

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # macOS / Linux
```

**2. 安装 JDK 21**——用 `java -version` 确认（必须是 21）：

```bash
# Debian/Ubuntu:  sudo apt install -y openjdk-21-jdk
# macOS:          brew install openjdk@21
# 其他:           Eclipse Temurin (https://adoptium.net)
```

**3. 安装 Ghidra 11.4.3**——下载并解压即可，无需安装程序、无需管理员权限：

```bash
curl -L -o ghidra.zip \
  https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.3_build/ghidra_11.4.3_PUBLIC_20251203.zip
unzip ghidra.zip -d ~/ghidra && rm ghidra.zip
export GHIDRA_HOME=~/ghidra/ghidra_11.4.3_PUBLIC   # 指向包含 support/analyzeHeadless 的那个目录
```

**4. 安装 Treasure Map：**

```bash
uv tool install --python 3.11 "git+https://github.com/JoeyZzZzZz/treasure-map.git"
```

**5. 初始化配置（一次即可）：**

```bash
tmap init
```

`init` 会写入 `~/.treasure-map/config.yaml`、从 `GHIDRA_HOME` 自动检测 Ghidra（或询问一次），并跑一遍预检。把它标 `❌` 的项修好、重跑一次；当没有 `❌` 时，就绪。

---

## 使用

把 Treasure Map 指向你解压好的固件根目录，一条命令：

```bash
tmap scan ./firmware.extracted -w router_v1
```

它会反编译每个二进制、建好这张事实底图——慢的是这一步（每个二进制跑一遍 Ghidra），带进度显示；可断点续跑，用同一个 `-w` 重跑就从上次检查点继续。随时可以再扫新固件，每个固件各自存在自己的 workspace 下。

**这是你唯一需要手动跑的命令。** 之后的一切——读排序线索、顺着它横跨固件去追、记录判断——都由你的 AI agent 通过 MCP server 来做 ↓

---

## 接入你的 AI agent

Treasure Map 内置一个 MCP（Model Context Protocol）server。**注册一次即可**——不用填路径、不用为每个固件单独配置。server 绑的是你**整个 `atlas`**（你扫过的所有固件构成的知识库）；**具体看哪个固件由 agent 自己选**，新扫的固件（`tmap scan`）无需重新配置就能用。

| Agent | 注册一次 |
|---|---|
| **Claude Code** | `claude mcp add -s user treasure-map -- tmap mcp` |
| **Codex（OpenAI）** | `codex mcp add treasure-map -- tmap mcp` |
| **Cursor / Windsurf / Gemini CLI / 其他 JSON 客户端** | 把下面的块加进该客户端的 MCP 配置文件 |

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

配置文件位置：Cursor `~/.cursor/mcp.json`，Windsurf `~/.codeium/windsurf/mcp_config.json`，Gemini CLI
`~/.gemini/settings.json`；VS Code —— `code --add-mcp '{"name":"treasure-map","command":"tmap","args":["mcp"]}'`。

然后，在你的 agent 里：

> 用 treasure-map 审计这个固件。从它的排序候选清单顶部往下看——打开某条线索的伪代码、往上游追、自己判断。它们是待验证的线索，不是已确认的漏洞。

---

## 现状

早期开发中——API 和行为可能变化。

- **稳定：** `scan` 流水线（analyze → hunt → triage）、面向 AI 的 MCP 事实层、标注层。sink 覆盖：命令执行、缓冲区拷贝、格式化字符串注入（均带函数内实参溯源），外加路径 sink（检测与排名）。
- **实验性：** `diff`（跨版本补丁对比）——正在积极开发中；不影响 `scan`。

---

## 用途与法律

**用途。** Treasure Map 服务于固件的防御性安全审计和漏洞研究。它产出候选发现和分析线索；按设计，它**不**生成 PoC、payload、shellcode 或任何可直接武器化的产物。

**合法使用由你负责。** 只分析你合法持有的固件——你拥有的设备，或厂商真正公开、且获取时**没有**绕过任何登录/付费墙/访问控制的固件。即便是合法获取的固件，也可能受许可、服务条款或合同对逆向工程的限制约束；审阅这些是你的责任。

**发现是候选，不是定论。** 输出需要独立的人工验证，不是已确认的漏洞。

**不提供任何担保。** 本工具按"原样"提供。你如何使用、以及确保你的行为在你所在司法辖区合法，完全由你负责。若不确定，请在动手前咨询合格的法律顾问。

---

## 疑难排查

- **`tmap: command not found`**——工具的 bin 目录还没进 PATH。跑 `uv tool update-shell`，再开一个新 shell。
- **`Ghidra : not found` / `not auto-detected`**——把 `~/.treasure-map/config.yaml` 里的 `ghidra.local.home` 设成你的 Ghidra 安装根目录；确认 `<根>/support/analyzeHeadless` 存在。（WSL：装 **Linux** 版 Ghidra、用 Linux 路径，别用 `/mnt/c/...`。）
- **`java: not on PATH`**——确认 `java -version` 报 **21**（装了多个就 `update-alternatives --config java`）。

修好任何一项后重跑 `tmap init` 再检查。

---

## 卸载

```bash
uv tool uninstall treasure-map
```

这会**保留 `~/.treasure-map/`**——你的配置，尤其是 **`atlas.db`**：那是跨固件、随每次运行累积、且从不重建的知识库。重装会重新用上它。要连 `atlas.db` 一起彻底清掉：`rm -rf ~/.treasure-map`（不可恢复——不建议）。

---

## 许可

[AGPL-3.0](LICENSE)。商业授权咨询请提 issue 或联系维护者。
