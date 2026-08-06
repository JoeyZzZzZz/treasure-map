# Treasure Map

[English](README.md) | [中文](README.zh.md)

**Treasure Map is a reconnaissance tool for AI-driven firmware vulnerability research.** Point it at
the filesystem unpacked from an IoT device's firmware, and it finds every place in the compiled code
that does something dangerous with data: runs a shell command, copies into a memory buffer, formats
a log string, or opens a file by path. For each one, it records what it can honestly determine —
where that data comes from, how the spot is reached — and, just as important, what it *can't*. Then
it hands that map to your AI coding agent (Claude Code, Cursor, Codex) to investigate, every lead
traceable to an exact binary, function, and address.

Like the map it's named for, it shows where to dig and marks the terrain honestly — where it's sure,
where it isn't — but never says "here's the treasure." Deciding which lead is a real bug, and
whether it's exploitable, is your AI's job. **Facts are the tool's job; reasoning is the model's.**

You run a single command to build the map; from there your AI does the work, through Treasure Map's
bundled MCP server.

---

## Why a substrate, not another scanner

A scanner hands you findings and a severity score — a verdict you then have to trust or re-check.
Treasure Map hands you facts instead. It never decides which candidate is a real bug or whether one
is exploitable; it does the half an AI can't do for itself — across a whole firmware, reproducibly,
it surfaces every dangerous lead and marks exactly what it knows, what it doesn't, and what it can't
yet tell. A modern agent reads and reasons about one function well; what it can't do is scan
a whole root filesystem — or a fleet across versions — completely and the same way twice. That gap
is the tool's job.

- **Tri-state honesty.** Every fact is YES, NO, or an explicit UNKNOWN — never "can't tell" dressed
  up as a confident answer. A dangerous sink is listed even when no input source is found inside its
  function (the controlled value may arrive through a caller), so the tool never silently drops a
  lead it couldn't fully trace.

- **Ranks by signal, never by verdict.** Candidates are ordered so stronger-signal leads surface
  first, but the tool never rules one in or out. Only a *proven-safe* fact can push a candidate down
  the list; an UNKNOWN never can. Re-sorting by any dimension re-ranks the view — it does not drop
  candidates. Reachability is graded one function at a time: this is **not** a taint-propagation
  engine, and it never claims a path is unreachable.

- **Leads, not verdicts.** It supplies facts, call chains, and reachability evidence — never a
  payload, PoC, or "this is exploitable." A candidate is a lead to verify, not a confirmed
  vulnerability.

- **Judgments that accumulate.** Your AI's own verdicts settle in an annotation layer over the
  read-only facts, so a multi-session audit picks up where it left off instead of starting fresh —
  and a judgment is flagged for re-review the moment the facts under it change.

The stronger the agent, the more useful this is: the tool gives an AI honest, complete inputs it
can't produce for itself, so the AI can reason deeper on top of them.

---

## Requirements

| You provide | Version | Why |
|---|---|---|
| **Ghidra** | 11.4.3 | decompiles every binary (headless) |
| **JDK** | 21 | required by Ghidra 11.4.3 — JDK 11/17 make it fail to launch |

You install Ghidra and JDK yourself; the install below sets up Treasure Map and the right Python for
you. **No API keys are required.** (A zero-setup Docker image bundling everything is planned.)

Treasure Map is a CLI (`tmap`) with a bundled AI-facing MCP server. It **runs on macOS and Linux**;
on Windows, use WSL.

**Input = an already-extracted firmware filesystem.** Unpacking the firmware image is outside
Treasure Map's scope — use whatever extraction tool you prefer, and point Treasure Map at the
resulting directory.

Ghidra 11.4.3 is the pinned, tested toolchain (and is required for the experimental `diff` stage);
`scan` itself works with any Ghidra 11.x, but pinning keeps results reproducible.

---

## Install

**1. Install [uv](https://docs.astral.sh/uv/)** (a single binary that also manages the right Python):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # macOS / Linux
```

**2. Install JDK 21** — check with `java -version` (must report 21):

```bash
# Debian/Ubuntu:  sudo apt install -y openjdk-21-jdk
# macOS:          brew install openjdk@21
# Other:          Eclipse Temurin (https://adoptium.net)
```

**3. Install Ghidra 11.4.3** — download and unzip it (no installer, no admin rights):

```bash
curl -L -o ghidra.zip \
  https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.3_build/ghidra_11.4.3_PUBLIC_20251203.zip
unzip ghidra.zip -d ~/ghidra && rm ghidra.zip
export GHIDRA_HOME=~/ghidra/ghidra_11.4.3_PUBLIC   # the folder that contains support/analyzeHeadless
```

**4. Install Treasure Map:**

```bash
uv tool install --python 3.11 "git+https://github.com/JoeyZzZzZz/treasure-map.git"
```

**5. Configure once:**

```bash
tmap init
```

`init` writes `~/.treasure-map/config.yaml`, detects Ghidra from `GHIDRA_HOME` (or asks once), and
runs a preflight check. Fix anything it marks `❌`, then re-run. When there's no `❌`, you're ready.

---

## Use it

Point Treasure Map at your extracted firmware root and run one command:

```bash
tmap scan ./firmware.extracted -w my-firmware
```

`-w` is the name you give this firmware's workspace — pick any label. It decompiles every binary and
builds the fact map — the slow part (one Ghidra pass per binary), with progress shown. Re-running
with the **same** `-w` is resume-safe: it continues from the last Ghidra checkpoint and skips
binaries already done. Give a **different** `-w` and you get a separate workspace, so you can keep
several firmwares side by side, each with its own results.

That's the only command you run by hand. Everything after — reading the ranked leads, chasing them
across the firmware, recording judgments — is done by your AI agent through the MCP server ↓

---

## Connect your AI agent

Treasure Map ships an MCP (Model Context Protocol) server. Register it **once** — no paths, no
per-firmware setup. The server binds your whole `atlas` (the knowledge base of everything you've
scanned); the **agent picks which firmware to work on** by `run_id`, and a new `tmap scan` is
available with no reconfiguration.

| Agent | Register once |
|---|---|
| **Claude Code** | `claude mcp add -s user treasure-map -- tmap mcp` |
| **Codex (OpenAI)** | `codex mcp add treasure-map -- tmap mcp` |
| **Cursor / Windsurf / Gemini CLI / other JSON clients** | add the block below to the client's MCP config file |

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

Config file: Cursor `~/.cursor/mcp.json`, Windsurf `~/.codeium/windsurf/mcp_config.json`, Gemini CLI
`~/.gemini/settings.json`; VS Code — `code --add-mcp '{"name":"treasure-map","command":"tmap","args":["mcp"]}'`.

Then just talk to your agent in plain language — you don't drive the tools, it does:

> Audit this firmware using treasure-map. Work down its ranked candidate list from the top — open a
> lead's pseudocode, trace it upstream, and judge it yourself. They're leads to verify, not
> confirmed bugs.

Under the hood the agent runs a simple loop over the MCP fact tools: **recall** the ranked
candidates (`list_candidates`), **fetch facts** for a lead (`explain_candidate`, `get_pseudocode`,
`get_callees`, `get_xrefs`, `get_strings`, `get_sink_provenance`, …), then **judge** — recording its
verdict in the annotation layer (`annotate`) over the read-only facts. Every fact tool routes by
`run_id` or by a candidate's `evidence_ref`, so one server serves every firmware you've scanned.

---

## Status

Early development — APIs and behaviors may change.

- **Stable:** the `scan` pipeline (analyze → hunt → triage), the AI-facing MCP fact layer, and the
  annotation layer. Sink coverage: command-execution, buffer-copy, and format-string-injection
  sinks come with in-function argument provenance; **path/file sinks are covered for detection and
  ranking** (no in-function argument provenance yet — their controllability comes from a text-level
  source read, honestly marked).
- **Experimental:** `diff` (cross-build patch comparison) — under active development; does **not**
  affect `scan`.

---

## Intended Use & Legal

**Purpose.** Treasure Map supports defensive security auditing and vulnerability research on
firmware. It produces candidate findings and analysis leads; by design it does **not** generate
proof-of-concept exploits, payloads, shellcode, or other directly weaponizable output.

**Lawful use is yours to ensure.** Only analyze firmware you lawfully possess — a device you own, or
firmware made genuinely public by its vendor and obtained **without** bypassing any login, paywall,
or access control. Even lawfully obtained firmware may carry license, terms-of-service, or
contractual restrictions on reverse engineering; you are responsible for reviewing them.

**Findings are candidates, not verdicts.** Output requires independent human verification and is not
a confirmed vulnerability.

**No warranty.** The tool is provided "as is." You are solely responsible for how you use it and for
ensuring your activity is lawful in your jurisdiction. If unsure, consult qualified legal counsel
before proceeding.

---

## Troubleshooting

- **`tmap: command not found`** — the tool's bin dir isn't on PATH. Run `uv tool update-shell`, then
  open a new shell.
- **`Ghidra : not found` / `not auto-detected`** — set `ghidra.local.home` in
  `~/.treasure-map/config.yaml` to your Ghidra install root; verify `<root>/support/analyzeHeadless`
  exists. (WSL: install the **Linux** build and use a Linux path, not `/mnt/c/...`.)
- **`java: not on PATH`** — ensure `java -version` reports **21** (`update-alternatives --config
  java` if you have several).

Re-run `tmap init` after any fix to re-check.

---

## Uninstalling

```bash
uv tool uninstall treasure-map
```

This **keeps `~/.treasure-map/`** — your config and especially **`atlas.db`**, the cross-firmware
knowledge base that accumulates across runs and is never rebuilt. Reinstalling reuses all of it. To
wipe everything including `atlas.db`: `rm -rf ~/.treasure-map` (not recoverable — not recommended).

---

## License

[AGPL-3.0](LICENSE). For commercial licensing, open an issue or contact the maintainer.
