#!/usr/bin/env bash
# Run this before every push: the checks of CI's lint, type-check, recall-integrity,
# vendor-neutrality, rescan-stamp, unit and integration jobs, in one chain. `set -e` stops at the
# first failure.
#
# Not run here (CI runs them): the Package job (builds the wheel and installs it into a fresh venv)
# and the Lowest-dependencies job (installs every direct dependency at its declared lower bound).
# The integration tests need Ghidra on PATH (analyzeHeadless); without it they are skipped here,
# and CI runs them against the pinned Ghidra.
set -euo pipefail

echo "==> ruff check"
ruff check src/ tests/

echo "==> ruff format --check"
ruff format --check src/ tests/

echo "==> mypy strict"
mypy src/

echo "==> recall-integrity checker self-test"
python scripts/check_recall_integrity.py --self-test

echo "==> binary-selector gate"
bash scripts/check-binary-selector-resolution.sh

echo "==> oss-exclusion gate"
bash scripts/check-oss-exclusion-retired.sh

echo "==> vendor neutrality (this branch against origin/main)"
if base="$(git merge-base HEAD origin/main 2>/dev/null)" && [ "$base" != "$(git rev-parse HEAD)" ]; then
    bash scripts/check-vendor-neutrality.sh "$base" HEAD
else
    echo "    (nothing ahead of origin/main to check)"
fi

echo "==> rescan stamp backstop (code stamps equal to HEAD~1 => the same fixture output)"
python scripts/rescan_same_stamp_check.py --base HEAD~1

echo "==> pytest unit"
python -m pytest tests/unit/ -q

echo "==> pytest integration"
python -m pytest tests/integration/ -q

echo ""
echo "All local checks passed (CI additionally builds and installs the wheel, and tests the"
echo "lowest dependency versions)."
