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

`tmap init` installs the toolchain for you — or reuses what you already have when it checks out:

| Tool | Version | Why |
|---|---|---|
| **JDK** | 21 (a JDK, not a JRE) | runs Ghidra 11.4.3 — JDK 11/17 make it fail to launch |
| **Ghidra** | 11.4.3 | decompiles every binary (headless) |
| **BinExport** | for Ghidra 11.4.3 | exports a binary for `tmap diff` |
| **BinDiff** | 8 | matches functions between two firmware versions for `tmap diff` |

Downloads come from pinned URLs and are checked against a pinned size and sha256 before anything is
unpacked. They go to `~/.treasure-map/toolchain/`. **No API keys are required.**

| Platform | Status |
|---|---|
| Linux x86_64 (including WSL2) | supported |
| macOS on Apple Silicon | supported |
| macOS on Intel | runs the same toolchain; not acceptance-tested |
| Linux arm64, native Windows | not supported (no Ghidra decompiler / BinDiff build); on Windows use WSL2 |

**Input = an already-extracted firmware filesystem.** Unpacking the firmware image is outside
Treasure Map's scope — use whatever extraction tool you prefer, and point Treasure Map at the
resulting directory.

---

## Install

```bash
curl -LsSf https://github.com/JoeyZzZzZz/treasure-map/releases/latest/download/install.sh | sh
```

The script prints its plan, installs [uv](https://docs.astral.sh/uv/) if it is missing (without
editing your shell rc), installs `tmap` (PyPI package `tmap-agents`) with a uv-managed Python 3.11,
and starts `tmap init`. `install.sh --dry-run` shows the plan and changes nothing. Already have uv?
`uv tool install --python 3.11 tmap-agents` then `tmap init` does the same.

`tmap init`:

1. **finds** an existing JDK 21, Ghidra 11.4.3, BinExport and BinDiff 8 (config, `GHIDRA_HOME`,
   `JAVA_HOME`, PATH, common install locations) and checks each one at file level;
2. **asks** for a path, or offers the pinned download, for anything missing;
3. **lists your agents** (Claude Code, Codex, Cursor, Claude Desktop, dsh) with the ones installed on
   this machine pre-selected — Space to unselect, Enter to confirm;
4. **shows the plan** (every download with its URL, size and sha256; every file it will change) and
   asks `Apply N changes? [Y/n]`;
5. **applies** it, then runs the **doctor** and prints how to use the two main features.

Run it again any time: an up-to-date setup reports "everything current, nothing to do". Useful flags:
`--dry-run` (plan only), `--yes` (no questions, downloads included; registers only the agents named
with `--client`), `--non-interactive` (no questions, no downloads), `--ghidra / --java-home /
--bindiff PATH` (use exactly this), `--offline DIR` / `--mirror URL` (archives from elsewhere, same
checksums). `tmap doctor` re-runs the checks and writes nothing.

> Ghidra remembers the JDK it last ran with (`java_home.save` in its settings directory). When tmap
> runs Ghidra 11.4.3 it records the JDK tmap uses there; a Ghidra 11.4.3 you start yourself without
> `JAVA_HOME` may then pick that JDK.

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

Treasure Map ships an MCP (Model Context Protocol) server, and `tmap init` registers it with the
agents you select. The server binds your whole `atlas` (the knowledge base of everything you've
scanned); the **agent picks which firmware to work on** by `run_id`, and a new `tmap scan` is
available with no reconfiguration. Restart the agent after registering.

To register by hand, the command is always `<absolute path of tmap> mcp` (`command -v tmap`):

| Agent | Register |
|---|---|
| **Claude Code** | `claude mcp add -s user treasure-map -- "$(command -v tmap)" mcp` |
| **Codex (OpenAI)** | `codex mcp add treasure-map -- "$(command -v tmap)" mcp` |
| **Cursor / Claude Desktop / other JSON clients** | add the block below to the client's MCP config file |
| **dsh** | `tmap init --client dsh` appends the entry to `~/.dsh/cordis.patch.yml` |

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

Config file: Cursor `~/.cursor/mcp.json`, Claude Desktop `~/Library/Application Support/Claude/
claude_desktop_config.json` (macOS), Windsurf `~/.codeium/windsurf/mcp_config.json`, Gemini CLI
`~/.gemini/settings.json`. Use `-s user` with Claude Code: a project-local entry of the same name
would hide it inside that project (`tmap doctor` points such entries out).

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

Run `tmap doctor` first: every check says ✅, ⚠ (works, worth knowing), `·` (information), ❌ or `?`
(could not be determined — never shown as ✅), and it exits non-zero on any ❌ or `?`.

- **`tmap: command not found`** — the tool's bin dir isn't on PATH. Run `uv tool update-shell`, then
  open a new shell.
- **`ghidra` / `java` / `bindiff` ❌** — run `tmap init` again; it offers the pinned download, or
  pass `--ghidra / --java-home / --bindiff PATH`. (WSL: keep everything on the Linux side, not under
  `/mnt/c/...`.)
- **`binexport` ❌ "two copies"** — Ghidra loads extensions from its own `Ghidra/Extensions` and from
  its user settings directory; remove one of the two.

---

## Uninstalling

```bash
tmap uninstall              # agent registrations + the toolchain tmap downloaded
uv tool uninstall tmap-agents
```

`tmap uninstall` removes only what `tmap init` recorded installing — never a JDK, Ghidra or BinDiff
you installed yourself — and **keeps `~/.treasure-map/`**: your config and especially **`atlas.db`**,
the cross-firmware knowledge base that accumulates across runs and is never rebuilt. Reinstalling
reuses all of it. `tmap uninstall --purge-data` also deletes the atlas and the workspaces after you
type the confirmation phrase (not recoverable — not recommended).

---

## License

[Apache-2.0](LICENSE).
