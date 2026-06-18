# Shared vendor-neutrality / strategy-vocabulary scanning.
#
# Sourced (never executed) by the git hooks (.githooks/pre-commit,
# .githooks/commit-msg) and by CI (scripts/check-vendor-neutrality.sh) so the
# detection logic lives in exactly one place. Pure POSIX-ish bash; no side effects
# on source beyond defining the TM_* variables and functions below.

# Regexes shared between the local hooks and the CI fallback. Defined here so a
# fix to one denylist applies everywhere at once.
TM_BANNED_VOCAB='\b(moat|shield)\b|盾|fix_quality|incomplete_patch_flag|fix_quality_score'
TM_PRIVDOC='treasure-map-notes|private (design )?notes|design note|PRD §|private notes dir'
TM_SECTREF='§[0-9]|PRD §|\b(DD|ED|FD)[0-9]\b'

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
