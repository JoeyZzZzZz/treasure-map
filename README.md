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
| API key(s) | — | only for LLM-assisted steps (`--summarize`, `hunt-*`); plain `tmap analyze` runs on Ghidra alone |

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

1. **Point Treasure Map at your extracted firmware filesystem root.** (How you unpacked the
   firmware is up to you — outside Treasure Map's scope.) Say you extracted to `./_firmware.extracted/`.

2. **Analyze.** Produces an `analysis.db` in the workspace; resume-safe (re-run with the same
   `--workspace` to continue):
   ```bash
   tmap analyze ./_firmware.extracted -w ./work
   ```
   Useful flags: `--summarize` (function summaries via the S-tier LLM; needs an S-tier key),
   `--skip-non-binary`, `--skip-ingester <KIND>`, `-c <config.yaml>`.

3. **Go further (optional)**, once you have one or more `analysis.db`:
   ```bash
   tmap hunt-pattern <analysis.db>        # call-sequence shape candidates
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

## Status

This project is in early development. APIs and behaviors will change.

## Upgrading from earlier versions

Treasure Map is at v0.x and the database schema is not yet stable. When
upgrading, delete existing workspace directories and re-run `tmap analyze`:

    rm -rf <your-workspace-directory>

## License

This project is licensed under [AGPL-3.0](LICENSE). See [LICENSE-FAQ.md](LICENSE-FAQ.md) for details.

For commercial licensing inquiries, please open an issue or contact the maintainer.
