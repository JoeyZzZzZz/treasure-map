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
| Python | ≥ 3.11 | runs Treasure Map |
| Ghidra | 11.x | decompiles every binary (headless) |
| JDK | 21 | required by Ghidra 11.x (older JDKs make Ghidra fail to launch) |
| API key(s) | — | only for LLM-assisted steps (`--summarize`, `hunt-*`); plain `tmap analyze` runs on Ghidra alone |

You install these yourself — Treasure Map does not download them for you. (A zero-setup Docker
image with everything bundled is planned; until then, follow the Setup below.)

Treasure Map's **input is an already-extracted firmware filesystem**. Unpacking the firmware image
is outside its scope — use whatever extraction tool you prefer; Treasure Map takes the resulting
directory.

## Setup

Do these **in order**. Each step starts with a quick check — if you already have it, skip to the
next step. By the end, `tmap` is installed and configured.

### Step 1 — Python 3.11+

Check: `python3.11 --version` (or `python3 --version`). If it reports **3.11 or newer**, skip to Step 2.

Install:
```bash
# Debian/Ubuntu (20.04 ships 3.8, 22.04 ships 3.10 — too old):
sudo apt update && sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update && sudo apt install -y python3.11 python3.11-venv
# macOS:                brew install python@3.11
# any OS (alternative): pyenv install 3.11      (https://github.com/pyenv/pyenv)
```

### Step 2 — JDK 21

Check: `java -version` — it must report **21**. If so, skip to Step 3. (Ghidra 11.x needs exactly
21; JDK 11/17 make it fail at launch. If you have several JDKs installed, select 21 with
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
directly contains `support/analyzeHeadless`. Note that path; you'll give it to `tmap init` in
Step 5. Then skip to Step 4 (don't reinstall).

Install (no installer — just download + unzip):
```bash
# Download the "ghidra_<ver>_PUBLIC_<date>.zip" asset (NOT "Source code") from:
#   https://github.com/NationalSecurityAgency/ghidra/releases
unzip ghidra_11.*_PUBLIC_*.zip -d ~/ghidra      # -> ~/ghidra/ghidra_11.x_PUBLIC/  (= the install root)
```
No admin rights needed. Remember the install root path (the folder containing `support/`) for Step 5.

### Step 4 — Install Treasure Map (pipx)

pipx gives a global `tmap` command with nothing to activate.
```bash
# Install pipx if you don't have it (one-time, no sudo):
python3 -m pip install --user pipx && python3 -m pipx ensurepath    # then open a new shell

# Install Treasure Map, pinned to your Python 3.11 from Step 1:
pipx install --python python3.11 "git+https://github.com/JoeyZzZzZz/treasure-map.git"
```
If your `python3.11` is at a nonstandard path, pass it in full (`--python /path/to/python3.11`).
If your default `python3` is already ≥ 3.11, you can omit `--python`. The `git+…` URL is fetched
with **git**, so make sure git is installed first (`sudo apt install -y git`). Later: `pipx
upgrade treasure-map` / `pipx uninstall treasure-map`.

### Step 5 — Configure: `tmap init`

```bash
tmap init
```
This writes `~/.treasure-map/config.yaml` plus your API keys, **asks for your Ghidra install
root** (paste the path from Step 3 — or it's accepted automatically if Ghidra is already on your
`PATH`/`GHIDRA_HOME`), and runs a doctor preflight. Fix anything it marks `❌` (see
[Troubleshooting](#troubleshooting)), then re-run `tmap init`. When it shows no `❌`, you're ready.

## Using it

1. **Point Treasure Map at your extracted firmware filesystem root.** (How you unpacked the
   firmware is up to you — outside Treasure Map's scope.) Say you extracted to
   `./_firmware.extracted/`.

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

**Alternatives:** export `GHIDRA_HOME` (in the shell that runs `tmap`, e.g. via `.bashrc`/`.zshrc`),
or add `<ghidra-root>/support` to your `PATH`.

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
- `tmap: command not found` right after `pipx install` — pipx's bin directory isn't on PATH yet.
  Run `python3 -m pipx ensurepath`, open a new shell, and confirm `~/.local/bin` is on your
  `PATH`. (If the shell suggests `apt install emboss`, ignore it — an unrelated package shipping
  a different `tmap`.)
- `requires a different Python: 3.8.x not in '>=3.11'` — your default Python is too old. Do Step 1,
  then `pipx install --python python3.11 "git+https://github.com/JoeyZzZzZz/treasure-map.git"`.

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

## CLI alias

The `tm` command is preserved as a deprecated alias for `tmap` to help
existing users transition. It will be removed in v0.3. New documentation
and examples use `tmap` exclusively.

## License

This project is licensed under [AGPL-3.0](LICENSE). See [LICENSE-FAQ.md](LICENSE-FAQ.md) for details.

For commercial licensing inquiries, please open an issue or contact the maintainer.
