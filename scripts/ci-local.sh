#!/usr/bin/env bash
# Run this before EVERY push. CI runs the same chain — if any step fails here,
# CI will fail too. Use `set -e` so the first failure stops the chain.
set -euo pipefail

echo "==> ruff check"
ruff check src/ tests/

echo "==> ruff format --check"
ruff format --check src/ tests/

echo "==> mypy strict"
mypy src/

echo "==> pytest unit"
pytest tests/unit/ -q

echo ""
echo "All CI-equivalent checks passed. Safe to push."
