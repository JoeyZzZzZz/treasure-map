# Security policy

**English** | [中文](#中文)

## Reporting a vulnerability

Please do not report a security vulnerability in Treasure Map through a public issue, discussion
or pull request. Report it privately on GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**
(<https://github.com/JoeyZzZzZz/treasure-map/security/advisories/new>).

Include what you can of:

- the version (`tmap --version`) and your OS;
- what an attacker controls (for example, a file inside the firmware filesystem being scanned)
  and what they gain;
- steps to reproduce — a small synthetic filesystem or file is best. Do not attach firmware you
  are not allowed to share.

## What to expect

Timelines are best effort:

- an acknowledgement within 7 days;
- a first assessment within 30 days;
- for a confirmed issue, a fix and a disclosure date agreed with you, normally within 90 days of
  the report. You are credited in the advisory and the changelog unless you would rather not be.

## Supported versions

Treasure Map is a developer preview: security fixes go into the newest release only. Upgrade with
`tmap update`.

## Scope

Treasure Map reads firmware nobody vouches for, so the firmware is attacker input, and so is
anything an agent reading that firmware asks the MCP server for. In scope is a weakness in
Treasure Map's own code that lets crafted input do any of the following:

- through a crafted filesystem given to `tmap scan` or `tmap diff`, run code, or make Treasure
  Map read, write or delete a file outside that filesystem that the attacker chooses (for example
  through symbolic links or file names);
- through an MCP tool call, read a file outside the firmware trees you scanned, the atlas and the
  workspaces, or change the firmware facts (the tools write only the annotation overlay);
- put text taken from the firmware into the MCP server's instructions or tool descriptions, where
  an agent would read it as Treasure Map's own words rather than as a tool result;
- get past the pinned size and sha256 checks on what `tmap init` downloads, or make `tmap init`,
  `tmap update` or `tmap uninstall` write or delete anything their plan does not show;
- give the agent that `tmap review run --agent claude-code` launches any tool beyond Treasure
  Map's own MCP tools.

Out of scope:

- a vulnerability in firmware you analyzed **with** Treasure Map: report it to the device's
  vendor (Treasure Map does not coordinate third-party disclosure);
- a bug in Ghidra, BinExport, BinDiff, the JDK, uv or your agent: report it upstream, unless the
  way Treasure Map uses that tool is what makes it exploitable;
- an agent following instructions it found in firmware content returned by a tool, as long as
  what it can then do stays inside the bounds above (the MCP server's instructions tell the agent
  that such content is untrusted data);
- a wrong or missing analysis result, such as a missed candidate or an odd ordering: open a
  normal issue;
- anything that needs an attacker who can already write to `~/.treasure-map`, your `PATH` or your
  agent's configuration.

## 中文

### 报告漏洞

请不要通过公开的 issue、讨论区或 pull request 报告 Treasure Map 的安全漏洞，而是在 GitHub 上私下报告：打开仓库的
**Security** 页签，选择 **Report a vulnerability**
（<https://github.com/JoeyZzZzZz/treasure-map/security/advisories/new>）。

请尽量附上：

- 版本（`tmap --version`）和操作系统；
- 攻击者能控制什么（例如被扫描的固件文件系统里的某个文件），能借此得到什么；
- 复现步骤，最好是一个小的人造文件系统或文件。请不要附上你无权分享的固件。

### 处理流程

时间是尽力而为的承诺：

- 7 天内确认收到；
- 30 天内给出初步评估；
- 确认的问题会和你约定修复与公开日期，一般在报告后 90 天内。除非你不希望署名，安全公告和更新日志里会致谢你。

### 支持的版本

Treasure Map 目前是开发者预览版，安全修复只进入最新的版本。用 `tmap update` 升级。

### 范围

Treasure Map 读取的是没有人担保过的固件，所以固件本身就是攻击者的输入；读这些固件的 agent 向 MCP
服务器发出的请求也一样。属于范围内的，是 Treasure Map 自身代码中的弱点，让精心构造的输入能够：

- 通过交给 `tmap scan` 或 `tmap diff` 的构造过的文件系统（例如借助符号链接或文件名），执行代码，或者让
  Treasure Map 读取、写入或删除这个文件系统之外、由攻击者选定的文件；
- 通过一次 MCP 工具调用，读取你扫描过的固件目录、atlas 和工作区之外的文件，或者改动固件事实（这些工具只写标注层）；
- 把来自固件的文字放进 MCP 服务器的说明或工具描述里，让 agent 把它当成 Treasure Map 自己的话，而不是工具返回的结果；
- 绕过 `tmap init` 下载内容的固定大小和 sha256 校验，或者让 `tmap init`、`tmap update`、`tmap uninstall`
  写入或删除计划里没有列出的东西；
- 让 `tmap review run --agent claude-code` 启动的 agent 拿到 Treasure Map 自身 MCP 工具之外的任何工具。

不属于范围内的：

- 你**借助** Treasure Map 在固件里发现的漏洞：请报告给设备厂商（Treasure Map 不负责协调第三方漏洞披露）；
- Ghidra、BinExport、BinDiff、JDK、uv 或你的 agent 自身的缺陷：请向上游报告，除非正是 Treasure Map
  的用法让它变得可利用；
- agent 听从了工具返回的固件内容里的指令，只要它因此能做的事仍在上面的边界之内（MCP 服务器的说明已告诉 agent 这类内容是不可信的数据）；
- 分析结果错误或缺失，例如漏掉一个候选、排序不合理：请正常提交 issue；
- 需要攻击者事先已能写入 `~/.treasure-map`、你的 `PATH` 或 agent 配置才能成立的问题。
