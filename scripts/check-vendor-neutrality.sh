#!/usr/bin/env bash
# CI backstop for vendor-neutrality. Runs the same detection logic as the local
# git hooks (.githooks/lib.sh) over a commit range, checking BOTH the diff content
# AND every commit message — so a violation lands even when the local hooks were
# never installed or were bypassed with --no-verify.
#
# Usage: check-vendor-neutrality.sh [BASE_REF] [HEAD_REF]
#   BASE_REF defaults to HEAD~1 (or, if absent/invalid, the diff scan is skipped
#   and only HEAD's message is checked). HEAD_REF defaults to HEAD.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
. "$ROOT/.githooks/lib.sh"

HEAD_REF="${2:-HEAD}"
BASE_REF="${1:-}"
if [ -z "$BASE_REF" ] || ! git rev-parse --verify --quiet "${BASE_REF}^{commit}" >/dev/null 2>&1; then
    BASE_REF="$(git rev-parse --verify --quiet "${HEAD_REF}~1^{commit}" 2>/dev/null || true)"
fi
RANGE="${BASE_REF:-<root>}..${HEAD_REF}"

WATCHLIST="$(tm_resolve_watchlist || true)"
if [ -z "$WATCHLIST" ]; then
    echo "no vendor watchlist resolved; nothing to check"
    exit 0
fi

fail=0

# ── 1) diff content over the range ───────────────────────────────────────────
# Exclude the hook machinery, the watchlists, and the hook's own test, whose
# denylist patterns would otherwise self-match.
if [ -n "$BASE_REF" ]; then
    ADDED=$(git diff "$BASE_REF" "$HEAD_REF" -U0 --diff-filter=ACM -- . \
            ":(exclude).githooks/vendor-watchlist.txt" \
            ":(exclude).githooks/vendor-watchlist.example.txt" \
            ":(exclude).githooks/pre-commit" \
            ":(exclude).githooks/commit-msg" \
            ":(exclude).githooks/lib.sh" \
            ":(exclude)tests/unit/test_precommit_hook.py" \
            ":(exclude)tests/unit/test_mcp_app.py" \
            | grep '^+' | grep -v '^+++' || true)

    if HITS=$(printf '%s' "$ADDED" | tm_scan_text "$WATCHLIST"); then :; else
        echo "❌ vendor identifier(s) in diff content ($RANGE):"
        echo "$HITS"
        fail=1
    fi

    SVHITS=$(printf '%s' "$ADDED" | grep -nIE "$TM_BANNED_VOCAB" || true)
    if [ -n "$SVHITS" ]; then
        echo "❌ strategy/judgment vocabulary in diff content ($RANGE):"
        echo "$SVHITS"
        fail=1
    fi

    PRIVHITS=$(printf '%s' "$ADDED" | grep -nIE "$TM_PRIVDOC" || true)
    if [ -n "$PRIVHITS" ]; then
        echo "❌ private-doc/path reference in diff content ($RANGE):"
        echo "$PRIVHITS"
        fail=1
    fi
fi

# ── 2) commit messages over the range ────────────────────────────────────────
# This is the path the local hooks historically missed: a model number can sit in
# the message even when the diff is clean.
RANGE_SPEC="${HEAD_REF}"
[ -n "$BASE_REF" ] && RANGE_SPEC="${BASE_REF}..${HEAD_REF}"
MSGS=$(git log --no-merges --format='commit %h: %s%n%b' "$RANGE_SPEC" 2>/dev/null || true)

if HITS=$(printf '%s' "$MSGS" | tm_scan_text "$WATCHLIST"); then :; else
    echo "❌ vendor identifier(s) in commit message(s) ($RANGE):"
    echo "$HITS"
    fail=1
fi

SVHITS=$(printf '%s' "$MSGS" | grep -nIE "$TM_BANNED_VOCAB" || true)
if [ -n "$SVHITS" ]; then
    echo "❌ strategy/judgment vocabulary in commit message(s) ($RANGE):"
    echo "$SVHITS"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "Vendor names / model numbers / strategy framing must never enter committed"
    echo "artifacts or commit messages. Replace with a generic category term and amend."
    exit 1
fi

echo "✓ vendor-neutrality: diff content + commit messages clean over $RANGE"
