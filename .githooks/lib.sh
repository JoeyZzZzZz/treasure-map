# Shared scanning for third-party firmware identifiers and private-note references.
#
# Sourced (never executed) by the git hooks (.githooks/pre-commit,
# .githooks/commit-msg) and by CI (scripts/check-vendor-neutrality.sh) so the
# detection logic lives in exactly one place. Pure POSIX-ish bash; no side effects
# on source beyond defining the TM_* variables and functions below.

# Regexes shared between the local hooks and the CI fallback. Defined here so a
# fix to one pattern applies everywhere at once.
TM_PRIVDOC='treasure-map-notes|private (design )?notes|design note|PRD §|private notes dir'
TM_SECTREF='§[0-9]|PRD §|\b(DD|ED|FD)[0-9]\b'

# ── shared diff pathspec exclude sets ────────────────────────────────────────
# One source of truth for BOTH the local hooks (git diff --cached) and the CI
# backstop (git diff BASE HEAD), so the two can never drift. Each site runs its
# own `git diff … -- . "${set[@]}"` and picks the set per the scan it is running.

# MACHINERY: files whose whole job is to hold scan patterns / real brand names
# verbatim — the hook scripts, the watchlists, and the hook's own test (which
# embeds real vendor tokens to prove detection). Exempt from EVERY scan; scanning
# them would only match their own pattern definitions.
TM_DIFF_MACHINERY_EXCLUDES=(
    ":(exclude).githooks/vendor-watchlist.txt"
    ":(exclude).githooks/vendor-watchlist.example.txt"
    ":(exclude).githooks/pre-commit"
    ":(exclude).githooks/commit-msg"
    ":(exclude).githooks/lib.sh"
    ":(exclude)tests/unit/test_precommit_hook.py"
)

# SELF-REFERENTIAL TESTS: tests that read project source and assert it does not
# cite the author's private notes — so each one NECESSARILY embeds those very
# tokens as literals. They are exempt from the private-note scan ONLY. The
# vendor-name scan still covers them — such a test has no business naming a brand
# — and each was verified brand-clean.
#
# ADMISSION RULE — the ONLY thing that may enter this list: a test whose body
# scans project source for the ABSENCE of private-note references. This is NOT a
# general escape hatch: anything else that trips a scan must be fixed in the
# source, never parked here.
TM_DIFF_SELF_REFERENTIAL_EXCLUDES=(
    ":(exclude)tests/unit/test_mcp_app.py"
    ":(exclude)tests/unit/lib/test_analyzer2.py"
    ":(exclude)tests/unit/lib/test_diff.py"
    ":(exclude)tests/unit/lib/test_diff_analyzer.py"
    ":(exclude)tests/unit/lib/test_downweight.py"
    ":(exclude)tests/unit/lib/test_pattern.py"
    ":(exclude)tests/unit/lib/test_reachability.py"
    ":(exclude)tests/unit/lib/test_triage_explain.py"
)

# Echo the watchlist path to use (env override -> local full list -> committed
# brand-free example). When falling back to the example, print a notice to stderr.
# Returns non-zero only if no watchlist file exists at all.
tm_resolve_watchlist() {
    local cand
    for cand in "${TM_VENDOR_WATCHLIST:-}" \
                ".githooks/vendor-watchlist.txt" \
                ".githooks/vendor-watchlist.example.txt"; do
        if [ -n "$cand" ] && [ -f "$cand" ]; then
            printf '%s\n' "$cand"
            if [ "$cand" = ".githooks/vendor-watchlist.example.txt" ]; then
                echo "ℹ️  vendor watchlist: using brand-free example (regex patterns only)." >&2
                echo "    Set TM_VENDOR_WATCHLIST to a full local list for brand-name coverage." >&2
            fi
            return 0
        fi
    done
    return 1
}

# Scan the text on stdin against every pattern in the watchlist ($1). Lines
# starting with [ or ( are PCRE (case-sensitive unless the pattern sets (?i));
# all other lines are literal whole-word, case-insensitive. Echoes a formatted
# block of hits to stdout and returns 1 if anything matched, else returns 0.
tm_scan_text() {
    local watchlist="$1"
    local text
    text="$(cat)"
    [ -z "$text" ] && return 0
    [ -f "$watchlist" ] || return 0

    local hits="" pat match
    while IFS= read -r pat; do
        case "$pat" in ''|\#*) continue ;; esac
        case "$pat" in
            \[*|\(*) match=$(printf '%s\n' "$text" | grep -P -- "$pat" || true) ;;
            *)        match=$(printf '%s\n' "$text" | grep -iwE -- "$pat" || true) ;;
        esac
        if [ -n "$match" ]; then
            hits="${hits}"$'\n'"  pattern: ${pat}"$'\n'"$(printf '%s' "$match" | sed 's/^/    /')"
        fi
    done < "$watchlist"

    if [ -n "$hits" ]; then
        printf '%s\n' "$hits"
        return 1
    fi
    return 0
}
