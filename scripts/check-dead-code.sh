#!/usr/bin/env bash
# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
#
# No dead code in the shipped package. Two passes of vulture over src/ only, so a function the
# TESTS still call but the product never reaches reads as unused — which is the shape this keeps
# finding: a helper a reader or writer stopped going through, left behind looking like a second
# way in, with its own tests still green around it.
#
# ruff's E,F,I,N,W,UP cannot see this: F401/F841 are per-file, and a module-level function with no
# caller anywhere is not a rule it has.
#
# PASS 1 — everything vulture is sure about (unused imports, unused locals).
# PASS 2 — unused functions and methods only. At this confidence vulture also reports unused
#   variables and attributes, and nearly all of those are false: a dataclass field read by name
#   out of a SQL row, a pydantic model field, a TypedDict key. Those are filtered out, so what is
#   left is the recurrence this guards. An unread CONSTANT is therefore NOT covered here.
#
# A framework calls some functions by a name it knows, never from our code; those are named below
# with what calls them. A new exemption needs that sentence too.
set -euo pipefail

cd "$(dirname "$0")/.."

# name:reason — each is reached by something outside this package.
EXEMPT=(
    "format_commands"      # click calls it to render --help (a Group method we override)
    "_clear_view_caches"   # the test suite's handle on the process-level view caches
    "clear_triage_cache"   # the same, for the per-run candidate reading (tests/conftest.py)
)

names="$(IFS='|'; echo "${EXEMPT[*]}")"

# This gate must never pass by not running. vulture 2.16's exit codes (measured, not guessed):
# 0 found nothing, 3 found something, 1 could not read a file (a missing path, a syntax error),
# 2 bad arguments. So only 0 and 3 are verdicts, and a bare `|| true` turned every other outcome
# — including vulture not being installed at all — into an empty report and a ✓.
# The same false green as a Ghidra job that passes by skipping: see TMAP_REQUIRE_GHIDRA in
# tests/integration/conftest.py.
command -v vulture >/dev/null || {
    echo "❌ dead-code gate: vulture is not on PATH, so this gate did not run." >&2
    echo "   pip install -e \".[dev]\"" >&2
    exit 1
}

VULTURE_OUT=""
# Deliberately not called inside a command substitution: in a subshell its `exit` would only end
# that subshell, and the `|| true` on the pipeline below would then swallow the failure.
run_vulture() {  # run_vulture <args...> -> findings in $VULTURE_OUT, or the gate fails
    local rc=0
    VULTURE_OUT="$(vulture "$@")" || rc=$?
    if [ "$rc" != 0 ] && [ "$rc" != 3 ]; then
        echo "❌ dead-code gate: vulture itself failed (exit $rc), so its verdict means nothing." >&2
        echo "   0 = nothing found, 3 = findings; 1 = a file it could not read, 2 = bad arguments." >&2
        exit 1
    fi
}

run_vulture src/treasure_map --min-confidence 80
sure="$VULTURE_OUT"
if [ -n "$sure" ]; then
    echo "$sure"
    echo "❌ dead code: the above is unused with no doubt (an import or a local)."
    exit 1
fi

# @field_validator / @click.command and friends: called by the framework, not from our code.
# grep exits 1 on no match, which here means "nothing left to report" — that `|| true` is right.
run_vulture src/treasure_map --min-confidence 60 \
    --ignore-decorators "@*.command,@*.group,@*.setter,@field_validator,@*.validator"
callable_dead="$(printf '%s\n' "$VULTURE_OUT" \
    | grep -E "unused (function|method)" \
    | grep -Ev "'($names)'" || true)"
if [ -n "$callable_dead" ]; then
    echo "$callable_dead"
    echo "❌ dead code: the shipped code calls none of the above. Delete it and have the tests go"
    echo "   through the entry point production uses — or, if a framework calls it, add it to"
    echo "   EXEMPT in $0 with the reason."
    exit 1
fi

echo "✓ dead-code gate: every function and method in src/ has a caller in src/"
