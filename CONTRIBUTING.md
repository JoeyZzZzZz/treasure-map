# Contributing to Treasure Map

Thank you for your interest in contributing to Treasure Map.

## Current Status

This project is in early development. We welcome:

- Bug reports
- Feature suggestions (via issues)
- Documentation improvements
- Benchmark sample contributions
- Configuration files and rule files

We currently do NOT accept:

- Pull requests for core algorithm changes (please open an issue first)
- New core capability additions (please open an issue first)

## Contributor License Agreement

All code contributions require signing a Contributor License Agreement 
(CLA). This will be automated via cla-assistant.io once we begin 
accepting code contributions.

## Reporting Bugs

Please open an issue with:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, etc.)

## Suggesting Features

Open an issue describing your use case and the feature you'd like to see.

## Development setup

End users install with `pipx` (see the README); contributors work from a clone in an
editable virtual environment instead:

```bash
git clone https://github.com/JoeyZzZzZz/treasure-map.git
cd treasure-map
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
./scripts/install-hooks.sh   # REQUIRED: activates the git hooks (see below)
```

**You must run `./scripts/install-hooks.sh` after cloning.** It points
`core.hooksPath` at `.githooks/` so the `pre-commit` and `commit-msg` checks
actually run. Git does not pick up `.githooks/` on its own — without this step the
hooks are inert and a vendor name or model number can slip into a commit or its
message locally. CI re-runs the same checks (the `vendor-neutrality` job) as a
backstop, so an un-installed hook surfaces as a failed PR rather than a clean
local commit, but installing the hooks catches it before you push.

Run the same checks CI runs before pushing:

```bash
./scripts/ci-local.sh    # ruff, ruff format --check, mypy strict, pytest
```

You still need Ghidra 11.x + JDK 21 on the host for `tmap analyze` (README → Setup) and
`tmap init` to configure them; the editable install does not bundle them.

## Vendor Denylist (git hooks + CI)

Vendor neutrality is enforced in three layers (all sharing `.githooks/lib.sh`):

- **`pre-commit`** scans the staged diff content.
- **`commit-msg`** scans the commit message (a model number must not hide there).
- **CI `vendor-neutrality`** re-scans both the diff and every commit message over
  the pushed range — the backstop for an un-installed hook or `--no-verify`.

The committed file `.githooks/vendor-watchlist.example.txt` contains only generic
model-number regex patterns (no brand names), including a lower-case run-together
form that whitelists common technical tokens (`sha256`, `base64`, `arm32`, …) so
they are not flagged. For full brand-name coverage, obtain the complete local
denylist from the project owner and point the hooks at it:

```bash
# Set TM_VENDOR_WATCHLIST to the path of your local denylist before committing:
export TM_VENDOR_WATCHLIST=/path/to/your/vendor-watchlist.txt
```

Without the full list the hooks and CI still block model-number-shaped strings via
the example template and print an informational notice.
