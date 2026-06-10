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

## Vendor Denylist (pre-commit hook)

The pre-commit hook enforces §5.5 vendor neutrality. The committed file
`.githooks/vendor-watchlist.example.txt` contains only generic model-number
regex patterns (no brand names). For full brand-name coverage, install the
complete local denylist:

```bash
mkdir -p ~/treasure-map-notes
# Obtain the full list from the project owner, then place it at:
# ~/treasure-map-notes/vendor-watchlist.txt
```

Alternatively, set `TM_VENDOR_WATCHLIST` to a custom path before committing.
Without the full list the hook still blocks model-number-shaped strings via
the example template and prints an informational notice.
