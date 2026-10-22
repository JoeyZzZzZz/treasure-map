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

# A RAM-backed temp dir when there is one and the caller set none: the tests create and commit to
# many small databases, and on a slow-fsync disk (a WSL2 virtual disk) that wait dominates the run.
# macOS has no /dev/shm, so there the temp dir is left as it is.
#
# Each run gets a directory of its own (it holds about 1 GB after a full run, in memory). It is
# removed when every check passed, and kept when one failed, so the failed tests' files can be
# read; the next run removes such leftovers, except one whose run is still going.
if [ -z "${TMPDIR:-}" ] && [ -d /dev/shm ] && [ -w /dev/shm ]; then
    for old in /dev/shm/tmap-ci.*; do
        [ -d "$old" ] && [ -O "$old" ] || continue
        pid="$(cat "$old/.ci-pid" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            continue  # another ci-local.sh run is still using it
        fi
        echo "==> removing the temp dir an earlier run kept: $old"
        rm -rf "$old"
    done
    TMPDIR="$(mktemp -d /dev/shm/tmap-ci.XXXXXX)"
    export TMPDIR
    echo "$$" > "$TMPDIR/.ci-pid"
    _ci_tmp_done() {
        local status=$?
        if [ "$status" -eq 0 ]; then
            rm -rf "$TMPDIR"
        else
            echo "==> a check failed: its temp files are kept in $TMPDIR (the next run removes them)" >&2
        fi
    }
    trap _ci_tmp_done EXIT
fi
echo "==> temp dir: ${TMPDIR:-default}"

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
