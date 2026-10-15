#!/usr/bin/env bash
# CI backstop for vendor-neutrality. Runs the same detection logic as the local
# git hooks (.githooks/lib.sh) over a commit range, checking BOTH the diff content
# AND every commit message — so a violation lands even when the local hooks were
# never installed or were bypassed with --no-verify.
#
# Usage: check-vendor-neutrality.sh [BASE_REF] [HEAD_REF]
#   BASE_REF absent or not a commit (a first push, a force-push over an unknown base): the WHOLE
#   tree at HEAD_REF is scanned, and HEAD_REF's own message. HEAD_REF defaults to HEAD.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
. "$ROOT/.githooks/lib.sh"

HEAD_REF="${2:-HEAD}"
BASE_REF="${1:-}"
WHOLE_TREE=0
if [ -z "$BASE_REF" ] || ! git rev-parse --verify --quiet "${BASE_REF}^{commit}" >/dev/null 2>&1; then
    # No usable base: diff against the empty tree, so every file at HEAD_REF is scanned. Only
    # looking at HEAD~1 here let everything before it through unseen.
    BASE_REF="$(git hash-object -t tree /dev/null)"
    WHOLE_TREE=1
fi
RANGE="${BASE_REF}..${HEAD_REF}"
[ "$WHOLE_TREE" -eq 1 ] && RANGE="whole tree at ${HEAD_REF}"

WATCHLIST="$(tm_resolve_watchlist || true)"
if [ -z "$WATCHLIST" ]; then
    echo "no vendor watchlist resolved; nothing to check"
    exit 0
fi

fail=0

# ── 1) diff content over the range ───────────────────────────────────────────
# Two diff views sharing one source of truth (.githooks/lib.sh):
#   ADDED_ALL     — everything but the pattern-holding machinery. The vendor-name
#                   scan runs here; a neutrality test must never name a brand, and
#                   every such test was verified brand-clean.
#   ADDED_FRAMING — ADDED_ALL minus the self-referential tests, which embed the
#                   private-note / section-ref literals they detect. The
#                   private-doc + section-ref scans run here.
if [ -n "$BASE_REF" ]; then
    # --no-renames: a renamed file is scanned whole, never skipped as "unchanged".
    ADDED_ALL=$(git diff "$BASE_REF" "$HEAD_REF" -U0 --no-renames --diff-filter=ACM -- . \
            "${TM_DIFF_MACHINERY_EXCLUDES[@]}" \
            | grep '^+' | grep -v '^+++' || true)
    ADDED_FRAMING=$(git diff "$BASE_REF" "$HEAD_REF" -U0 --no-renames --diff-filter=ACM -- . \
            "${TM_DIFF_MACHINERY_EXCLUDES[@]}" ${TM_DIFF_SELF_REFERENTIAL_EXCLUDES[@]+"${TM_DIFF_SELF_REFERENTIAL_EXCLUDES[@]}"} \
            | grep '^+' | grep -v '^+++' || true)

    PATHS=$(git diff "$BASE_REF" "$HEAD_REF" --name-only --no-renames --diff-filter=ACM -- . \
            "${TM_DIFF_MACHINERY_EXCLUDES[@]}" || true)
    if HITS=$(printf '%s\n%s' "$ADDED_ALL" "$PATHS" | tm_scan_text "$WATCHLIST"); then :; else
        echo "❌ vendor identifier(s) in diff content or file names ($RANGE):"
        echo "$HITS"
        fail=1
    fi

    PRIVHITS=$(printf '%s' "$ADDED_FRAMING" | grep -nIE "$TM_PRIVDOC" || true)
    if [ -n "$PRIVHITS" ]; then
        echo "❌ private-doc/path reference in diff content ($RANGE):"
        echo "$PRIVHITS"
        fail=1
    fi

    SECTHITS=$(printf '%s' "$ADDED_FRAMING" | grep -nIE "$TM_SECTREF" || true)
    if [ -n "$SECTHITS" ]; then
        echo "❌ private-doc section/design-code reference in diff content ($RANGE):"
        echo "$SECTHITS"
        fail=1
    fi
fi

# ── 2) commit messages over the range ────────────────────────────────────────
# This is the path the local hooks historically missed: a model number can sit in
# the message even when the diff is clean.
RANGE_SPEC="${BASE_REF}..${HEAD_REF}"
# Without a base, only HEAD_REF's own message: the history before it is not this push's.
[ "$WHOLE_TREE" -eq 1 ] && RANGE_SPEC="-1 ${HEAD_REF}"
# Scan ONLY the human-written subject + body (%s%n%b). The git-generated short hash (%h) is
# deliberately NOT included: a hex short hash can incidentally match the model-number regex
# ([a-z]{2,6}[0-9]{3,}) — that is unrelated to vendor neutrality and would redden CI on a false
# positive (also the source of test_ci_backstop_passes_clean_range's intermittent flake).
# Merge commits included: a merge message can name a branch, and a branch name can carry one.
# shellcheck disable=SC2086  # RANGE_SPEC is "-1 <ref>" or "<a>..<b>", split on purpose
MSGS=$(git log --format='%s%n%b' $RANGE_SPEC 2>/dev/null || true)

if HITS=$(printf '%s' "$MSGS" | tm_scan_text "$WATCHLIST"); then :; else
    echo "❌ vendor identifier(s) in commit message(s) ($RANGE):"
    echo "$HITS"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "Vendor names / model numbers must never enter committed artifacts or"
    echo "commit messages. Replace with a generic category term and amend."
    exit 1
fi

echo "✓ vendor-neutrality: diff content + commit messages clean over $RANGE"
