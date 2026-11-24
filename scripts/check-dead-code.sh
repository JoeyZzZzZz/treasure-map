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
)

names="$(IFS='|'; echo "${EXEMPT[*]}")"

sure="$(vulture src/treasure_map --min-confidence 80 || true)"
if [ -n "$sure" ]; then
    echo "$sure"
    echo "❌ dead code: the above is unused with no doubt (an import or a local)."
    exit 1
fi

# @field_validator / @click.command and friends: called by the framework, not from our code.
callable_dead="$(vulture src/treasure_map --min-confidence 60 \
    --ignore-decorators "@*.command,@*.group,@*.setter,@field_validator,@*.validator" \
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
