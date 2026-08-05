# Treasure Map

[English](README.md) | [中文](README.zh.md)

Treasure Map turns extracted IoT firmware into an honest, re-derivable fact substrate your AI
reasons over — the model does the vulnerability reasoning; the tool guarantees the model's inputs
are complete, deterministic, and not something it produced on its own.

Point it at an extracted firmware filesystem. It decompiles every binary, locates dangerous sink
callsites, records where each sink argument's value comes from within its function, and grades how
reachable each one is — then hands your AI co-pilot (Claude Code, Cursor, Codex, and others) a
ranked, evidence-anchored candidate list, every lead traceable to a binary, function, and address.
Facts are the tool's job; reasoning is the model's. Treasure Map does its half completely so your
AI can do its half best.

**What makes it a substrate, not another scanner:**

- **Tri-state honesty.** Every fact is YES, NO, or an explicit UNKNOWN — it never dresses "can't
  tell" as a confident answer. A dangerous sink is listed even when no input source is found inside
  the function (the controlled value may arrive through a caller), and known low-yield forms sink to
  the bottom of the list but are never dropped.
- **Leads, not verdicts.** It supplies facts, chains, and reachability evidence — never a payload,
  PoC, or "this is exploitable." You, or your AI, judge and verify.
- **Judgments that accumulate.** Your AI's own verdicts settle in an annotation layer over the
  read-only facts, so a multi-session audit picks up where it left off instead of starting fresh —
  and a judgment is flagged for re-review the moment the facts under it change.

CLI: `tmap`, with a bundled AI-facing MCP server. **Runs on macOS and Linux** (on Windows, use WSL).

---

## Requirements

| You provide | Version | Why |
|---|---|---|
| **Ghidra** | 11.4.3 | decompiles every binary (headless) |
| **JDK** | 21 | required by Ghidra 11.4.3 — JDK 11/17 make it fail to launch |

You install Ghidra and JDK yourself; the install below sets up Treasure Map and the right Python
for you. **No API keys are required.** (A zero-setup Docker image bundling everything is planned.)

**Input = an already-extracted firmware filesystem.** Unpacking the firmware image is outside
Treasure Map's scope — use whatever extraction tool you prefer, and point Treasure Map at the
resulting directory.

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
tmap scan ./firmware.extracted -w router_v1
```

It decompiles every binary and builds the fact map — the slow part (one Ghidra pass per binary),
with progress shown; resume-safe, so re-running with the same `-w` continues from the last
checkpoint. Scan a new firmware whenever you like; each is kept under its own workspace.

That's the only command you run by hand. Everything after — reading the ranked leads, chasing them
across the firmware, recording judgments — is done by your AI agent through the MCP server ↓

---

## Connect your AI agent

Treasure Map ships an MCP (Model Context Protocol) server. Register it **once** — no paths, no
per-firmware setup. The server binds your whole `atlas` (the knowledge base of everything you've
scanned); the **agent picks which firmware to work on**, and a new `tmap scan` is available with no
reconfiguration.

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

Then, in your agent:

> Audit this firmware using treasure-map. Work down its ranked candidate list from the top — open
> a lead's pseudocode, trace it upstream, and judge it yourself. They're leads to verify, not
> confirmed bugs.

---

## Status

Early development — APIs and behaviors may change.

- **Stable:** the `scan` pipeline (analyze → hunt → triage), the AI-facing MCP fact layer, and the
  annotation layer. Sink coverage: command-execution, buffer-copy, and format-string-injection
  sinks (with in-function argument provenance), plus path sinks (detection and ranking).
- **Experimental:** `diff` (cross-build patch comparison) — under active development; does not
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

- **`tmap: command not found`** — the tool's bin dir isn't on PATH. Run `uv tool update-shell`,
  then open a new shell.
- **`Ghidra : not found` / `not auto-detected`** — set `ghidra.local.home` in
  `~/.treasure-map/config.yaml` to your Ghidra install root; verify
  `<root>/support/analyzeHeadless` exists. (WSL: install the **Linux** build and use a Linux path,
  not `/mnt/c/...`.)
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
