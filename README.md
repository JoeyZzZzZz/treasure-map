# Treasure Map

Treasure Map is a static analysis tool for IoT firmware research.

Given an extracted firmware filesystem, it decompiles every binary,
traces data flow from external input sources to sensitive sinks, and
produces structured analyses optimized for AI-assisted reasoning.

Designed for security researchers who reverse IoT firmware and want
their AI co-pilot (Claude Code, Cursor, ChatGPT) to do the heavy
lifting on vulnerability understanding.

CLI: `tmap`. AGPL-3.0.

## What you'll need

| Dependency | Version | Why |
|---|---|---|
| Ghidra | 11.x | decompiles every binary (headless) |
| JDK | 21 | required by Ghidra 11.x (older JDKs make Ghidra fail to launch) |
| API key(s) | — | only for the LLM fallback in `hunt-diff` (stripped/renamed residue); `tmap analyze`, `hunt-pattern`, and `hunt-diff --max-assist 0` run with no key |

You install Ghidra and JDK yourself; the Setup below installs Treasure Map and the right Python
for you. (A zero-setup Docker image with everything bundled is planned; until then, follow Setup.)

Treasure Map's **input is an already-extracted firmware filesystem**. Unpacking the firmware image
is outside its scope — use whatever extraction tool you prefer; Treasure Map takes the resulting
directory.

## Setup

Do these **in order**. Each step starts with a quick check — if you already have it, skip ahead.

### Step 1 — Install uv

[uv](https://docs.astral.sh/uv/) is a single binary that installs Treasure Map and manages the
correct Python for it (no system Python or apt/PPA needed).

```bash
# Linux / macOS:
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"        # or just open a new shell so `uv` is on PATH
# Windows (PowerShell):  irm https://astral.sh/uv/install.ps1 | iex
# Already have it? `uv --version` → skip to Step 2.
```

### Step 2 — JDK 21

Check: `java -version` — it must report **21**. If so, skip to Step 3. (Ghidra 11.x needs exactly
21; JDK 11/17 make it fail at launch. With several JDKs installed, select 21 via
`sudo update-alternatives --config java`.)

Install:
```bash
# Debian/Ubuntu 24.04+:
sudo apt install -y openjdk-21-jdk
# macOS:  brew install openjdk@21
# Older Ubuntu / other distros: Eclipse Temurin (https://adoptium.net) or SDKMAN (sdk install java 21-tem)
```

### Step 3 — Ghidra 11.x

Check: if Ghidra 11.x is **already installed**, find its **install root** — the directory that
directly contains `support/analyzeHeadless` — and go straight to "Make it discoverable" below
(don't reinstall).

Install (no installer — just download + unzip):
```bash
# Download the "ghidra_<ver>_PUBLIC_<date>.zip" asset (NOT "Source code") from:
#   https://github.com/NationalSecurityAgency/ghidra/releases
unzip ghidra_11.*_PUBLIC_*.zip -d ~/ghidra      # -> ~/ghidra/ghidra_11.x_PUBLIC/  (= the install root)
```
No admin rights needed.

**Make it discoverable.** Point `GHIDRA_HOME` at the install root (the folder containing
`support/`) so the next steps find Ghidra automatically:
```bash
export GHIDRA_HOME=~/ghidra/ghidra_11.x_PUBLIC      # use your actual install root
```
Run Steps 4–5 in **this same shell**. `tmap init` (Step 5) detects `GHIDRA_HOME` and **writes the
path into `config.yaml`**, so it persists afterward — you don't need to keep `GHIDRA_HOME` set in
future shells, and you don't paste any path by hand.

### Step 4 — Install Treasure Map

One command. uv fetches a managed CPython 3.11, builds Treasure Map in an isolated environment,
and puts the `tmap` command on your PATH — nothing to activate.

```bash
uv tool install --python 3.11 "git+https://github.com/JoeyZzZzZz/treasure-map.git"
tmap --help
```

(The `git+…` URL is fetched with **git**, so make sure git is installed — `sudo apt install -y
git`. Later: `uv tool upgrade treasure-map` / `uv tool uninstall treasure-map`.)

### Step 5 — Configure: `tmap init`

```bash
tmap init
```
This writes `~/.treasure-map/config.yaml` plus your API keys and runs a doctor preflight. If you
set `GHIDRA_HOME` in Step 3 (or Ghidra is on your `PATH`), init **detects it and saves the path to
`config.yaml` automatically — no prompt**. Otherwise it asks once for the install root and
remembers it. Fix anything it marks `❌` (see [Troubleshooting](#troubleshooting)), then re-run
`tmap init`. When it shows no `❌`, you're ready.

> **Prefer pipx?** If you already have a Python ≥ 3.11 and use pipx, you can substitute Step 1+4
> with `pipx install --python python3.11 "git+https://github.com/JoeyZzZzZz/treasure-map.git"`
> (install a 3.11 first if needed — e.g. deadsnakes PPA, or `pyenv install 3.11`). uv is
> recommended because it brings its own Python and needs no PPA.

## Using it

**Point Treasure Map at your extracted firmware filesystem root** first. (How you unpacked the
firmware is up to you — outside Treasure Map's scope.) Say you extracted to `./_firmware.extracted/`.

### The main path — one command

```bash
tmap scan ./_firmware.extracted -w router_v1
```

`tmap scan` runs the whole pipeline — **analyze → hunt → triage** — and ends by printing a
**ranked, ready-to-act candidate list**: the functions worth reverse-engineering first, each with
an `evidence_ref` (`{run_id}#fn{func_id}@{sink}`) anchor and — printed under the row as `in: …` —
the **full path of the binary to open** in your decompiler, so a candidate in a firmware of
hundreds of binaries is directly actionable. It is slow in the **analyze** stage (one Ghidra JVM per
binary) and shows **per-stage progress** so you can see it working; the last stage is the same
readable triage table as `tmap triage`.

The ranking is a **review order** — `scan` scales up *finding candidates*; confirming a candidate
into a real issue is the manual reverse-engineering work, and stays yours. Gated (filtered/dormant)
candidates fold by default (`--include-gated` to show); `--top N`, `--status`, `--json` tune the
output. `--run-id` defaults to the workspace name (keep it **one run-id per device + firmware
version**).

### Or run the steps individually

Use these when you need to **re-run a single stage** — analyze is slow, hunt/triage are fast, and
the two stores decouple on purpose (`analysis.db` is wipe-and-rebuild; the atlas is append-only).

```bash
tmap analyze ./_firmware.extracted -w router_v1                                  # -> analysis.db
tmap hunt-pattern router_v1/analysis.db --run-id router_v1                       # -> atlas
tmap triage router_v1                # ranked globally by score; lower # = look first (top reachable on top)
tmap triage router_v1 --explain 1    # explain rank #1 (also accepts --explain <evidence_ref>)
```

`tmap triage` lists candidates in one global score-descending order — the `#` is a **stable rank**
(1 = highest, look first) that names the same candidate regardless of `--top`/`--status`/`--sink`, so
you can pass it straight to `--explain`. Each row prints, under it, `in: <binary path>` — the binary
to open in your decompiler. That location is stored in the atlas, so candidates stay locatable **even
after the per-firmware `analysis.db` is wiped/rebuilt**.

The list **caps at 20 by default** (it tells you when more exist). To see past the cap: `--all` shows
every candidate, and **`--sink <x>` shows every candidate for one sink, uncapped and across all
statuses** — by callee (`--sink system`, `popen`, `execl`, `strcpy`) or class (`--sink cmd|copy|
format`). Use `--sink system` when a recalled sink you care about is scored low and would otherwise
sit below the default cap.

**Recall before precision.** A dangerous sink callsite (`system`/`popen`/`exec*`, `strcpy`/`memcpy`/…)
is listed as a candidate even when no input source is recognized inside the function — the
controlled value may arrive through a caller, and a candidate that is never listed is the most
hidden false negative. Known low-yield forms are then **ranked low, never dropped**: a bare sink
with no in-function source, an exec sink that bypasses the shell, a value the function numerically
validates, a constant passed in by the sole caller, and code recognized as a third-party library
(by symbol) all sink to the bottom of their tier so the real source→sink shapes float up — but
every one stays a listed candidate you can still pull up with `--sink`/`--all`. `--explain <#|evidence_ref>` opens a single candidate: an itemized
breakdown of **why its score is what it is** (each point maps to a real signal), the call structure,
the **honest bounds** (reachability is single-function/L1, no caller traced, no cross-function flow;
`external_input` is a class label, not a trace), and a **manual-verify checklist** with anchors. It
explains evidence so you (or an AI) can judge and verify — it does **not** declare the candidate a
real issue and prints **no triggering input**.

**`-w/--workspace` takes a name *or* a path:**
- a **bare name** (`-w router_v1`) is managed for you under your workspace base —
  `~/.treasure-map/workspaces/router_v1` (the base is set in `tmap init`);
- a value with a **slash, `~`, `.`, or an absolute path** (`-w /mnt/scratch/fw1`, `-w ./work`)
  is used **as a literal path** — use this to put a workspace on a large/scratch/external disk;
- **omitted**, it defaults to an auto name under the base (derived from the firmware dir), shown
  in the output.

Analysis is **resume-safe**: re-run with the **same** `-w` to continue from the last checkpoint.
Useful flags: `--skip-non-binary`, `--skip-ingester <KIND>`, `-c <config.yaml>`.

**Go further (optional)**, once you have one or more `analysis.db`:
```bash
tmap hunt-diff <old.db> <new.db> ...   # diff two builds, grade reachability
tmap atlas-view ...                     # neutral cross-firmware aggregation
```

## Pointing Treasure Map at Ghidra

Used in Step 5 and at analyze time. Treasure Map locates Ghidra's `analyzeHeadless` by checking,
**in order**:

1. `ghidra.local.home` in `~/.treasure-map/config.yaml` → expects `<home>/support/analyzeHeadless`
2. the `GHIDRA_HOME` environment variable → expects `$GHIDRA_HOME/support/analyzeHeadless`
3. `analyzeHeadless` on your `PATH`

It does **not** scan your disk — if none of the three points at Ghidra, it reports
*not detected* even when Ghidra is installed.

**Recommended (option 1 — shell-independent, survives new terminals):** `tmap init` writes this
for you from the path you give it; or edit `config.yaml`:

```yaml
ghidra:
  local:
    home: /path/to/ghidra_11.x_PUBLIC
```

**Alternatives:** export `GHIDRA_HOME` (in the shell that runs `tmap`), or add
`<ghidra-root>/support` to your `PATH`.

Two things that trip people up:
- **Point at the install *root*** — the directory that directly contains `support/`. The test is
  simply: `<your path>/support/analyzeHeadless` must exist.
- **Windows/WSL:** the detector looks for `analyzeHeadless` (Linux/macOS). On native Windows the
  launcher is `analyzeHeadless.bat`; in WSL, install the **Linux** build of Ghidra and use a
  Linux path, not a Windows `/mnt/c/...` one.

`GHIDRA_HOME` is configuration, not a secret, so it is **not** stored in `.env` — use `config.yaml`
(option 1) for a persistent setup.

## Troubleshooting

**Install:**
- `tmap: command not found` after install — the tool's bin directory isn't on PATH yet. For uv:
  `uv tool update-shell`, then open a new shell. For pipx: `pipx ensurepath`. Confirm
  `~/.local/bin` is on your `PATH`. (If the shell suggests `apt install emboss`, ignore it — an
  unrelated package shipping a different `tmap`.)

**`tmap init` doctor** prints `name: ✅/❌ detail`. Common ❌ and fixes:

| Doctor line | Fix |
|---|---|
| `ghidra: ... not found` / *not detected* | Set `ghidra.local.home` in `config.yaml` (above) to your Ghidra install root. Verify `<root>/support/analyzeHeadless` exists. |
| `java: not on PATH` | Do Step 2; ensure `java -version` reports **21** (`update-alternatives --config java` if you have several). |
| `key:DEEPSEEK_API_KEY` / `key:ANTHROPIC_API_KEY: not set` | Provide the keys for your configured LLM tiers (defaults use DeepSeek + Anthropic). Re-run `tmap init` and paste them, or add them to `~/.treasure-map/.env`. Not required for plain `tmap analyze`. |
| `atlas_dir` / `workspace_dir: not writable` | Ensure `~/.treasure-map/` (and any custom paths in `config.yaml`) are writable. |

Re-run `tmap init` after any fix to re-check.

## Intended Use & Legal

**Purpose.** Treasure Map supports defensive security auditing and
vulnerability research on firmware. It produces candidate findings and
analysis leads; by design it does **not** generate proof-of-concept
exploits, payloads, shellcode, or other directly weaponizable output.

**Lawful use is yours to ensure.** Only analyze firmware you lawfully
possess — e.g. a device you own, or firmware made genuinely public by its
vendor and obtained **without** bypassing any login, paywall, or access
control. Even lawfully obtained firmware may be subject to license,
terms-of-service, or contractual restrictions on reverse engineering; you
are responsible for reviewing them.

**Findings are candidates, not verdicts.** Output requires independent
human verification and is not a confirmed vulnerability.

**No warranty; your responsibility.** The tool is provided "as is," without
warranty of any kind. You are solely responsible for how you use it and for
ensuring your activity is lawful in your jurisdiction. If you are unsure
whether a given analysis is permitted, consult qualified legal counsel
before proceeding.

## Status

This project is in early development. APIs and behaviors will change.

## Uninstalling

Remove the tool itself — this leaves your data and config untouched:
```bash
uv tool uninstall treasure-map        # or, if you used pipx:  pipx uninstall treasure-map
```

Uninstalling **deliberately keeps `~/.treasure-map/`** — your `config.yaml`, API keys (`.env`),
and especially **`atlas.db`**, the cross-firmware knowledge base that accumulates across runs and
is never rebuilt. Reinstalling and running `tmap init` again simply reuses all of it (init is
idempotent — it detects existing config and doesn't overwrite it; pass `--force` only if you want
to regenerate `config.yaml`).

If you truly want to wipe everything — keys, config, workspaces, **and the accumulated
`atlas.db`**:
```bash
rm -rf ~/.treasure-map        # deletes your API keys AND atlas.db — not recoverable
```
**Not recommended.** `atlas.db` is the analysis data you've built up over time; deleting it throws
that away for good. Across upgrades and reinstalls, prefer leaving `~/.treasure-map/` in place.

## License

This project is licensed under [AGPL-3.0](LICENSE). See [LICENSE-FAQ.md](LICENSE-FAQ.md) for details.

For commercial licensing inquiries, please open an issue or contact the maintainer.
