#!/usr/bin/env bash
# Regenerate the committed layer-0 .BinDiff fixture from the synthetic sources next to it.
#
# The fixture is REAL BinDiff runtime output — the parse tests are meant to read what the tool
# actually emits, not a hand-built SQLite table that agrees with our own reading of it. What is
# synthetic is the SUBJECT: two variants of a C file written for this repository (src/shapes_*.c).
# Nothing here derives from any firmware or third-party binary.
#
# Requires the same real toolchain the diff stage needs, so it does not run in CI:
#   Ghidra 11.4.3 (GHIDRA_HOME, or ~/ghidra/ghidra_11.4.3_PUBLIC) with the BinExport extension,
#   the `bindiff` CLI, and gcc.
#
# Usage:  tests/fixtures/layer0/make_fixture.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="$HERE/shapes_before_vs_shapes_after.BinDiff"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# -O1 keeps the identical wrappers as separate real functions: at -O2 they are folded or inlined
# and the pairing ambiguity the tests are about disappears. -g0 and a suppressed build id keep the
# two builds differing only where the sources differ.
for side in before after; do
    gcc -shared -fPIC -O1 -g0 -Wl,--build-id=none \
        -o "$WORK/shapes_$side.so" "$HERE/src/shapes_$side.c"
    # Strip local symbols. Without this BinDiff matches the identical wrappers by NAME and reports
    # high confidence for every one, and the ambiguity the fixture exists to capture never appears.
    # Stripped is also the normal state of the binaries this tool actually reads.
    strip --strip-all "$WORK/shapes_$side.so"
done

# This imports tmap's own driver, so it needs tmap's dependencies — prefer the repo venv.
PY_BIN="${PYTHON:-}"
if [ -z "$PY_BIN" ] && [ -x "$REPO/.venv/bin/python" ]; then
    PY_BIN="$REPO/.venv/bin/python"
fi
PY_BIN="${PY_BIN:-python3}"

"$PY_BIN" - "$REPO" "$WORK" "$OUT" <<'PYEOF'
import shutil
import sys
import tempfile
from pathlib import Path

repo, work, out = (Path(a) for a in sys.argv[1:4])
sys.path.insert(0, str(repo / "src"))
from treasure_map.lib.config.config import Config
from treasure_map.lib.diff.driver import _run_binexport, _run_bindiff

cfg = Config()
with tempfile.TemporaryDirectory(prefix="tm_fixture_") as td:
    d = Path(td)
    a = _run_binexport(work / "shapes_before.so", cfg, d, "before", 600)
    b = _run_binexport(work / "shapes_after.so", cfg, d, "after", 600)
    shutil.copy(_run_bindiff(a, b, d, 600), out)
PYEOF

echo "regenerated: $OUT"
