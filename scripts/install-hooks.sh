#!/usr/bin/env bash
# Install the repo's git hooks by pointing core.hooksPath at .githooks/.
# Run once after cloning. Without this, the vendor-neutrality checks in
# .githooks/ never run locally and only CI catches violations.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
git -C "$ROOT" config core.hooksPath .githooks

echo "✓ core.hooksPath set to .githooks"
echo "  Active hooks: $(ls "$ROOT/.githooks" | grep -vE '\.(sh|txt)$' | tr '\n' ' ')"
echo "  These run on every commit. CI re-checks the same rules as a backstop."
