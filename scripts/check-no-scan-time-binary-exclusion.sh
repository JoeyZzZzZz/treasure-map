#!/usr/bin/env bash
# The shape scan skips no binary.
#
# It used to skip whole binaries by name — a components-table membership test plus a list of
# generic project names plus "anything called lib*". That was a RECALL decision taken at scan
# time, on a label rather than on the code, and its only trace was a CLI counter: a reader of the
# result could not tell "looked and found nothing" from "never looked". Which project a binary
# came from belongs on the read side, where it can be weighed with everything else known about a
# candidate.
#
# This gate only stops the identifiers coming back. What the scan actually does is held by the
# runtime invariant in scanner.shape_scan_invariant_holds, by Gate D in check_recall_integrity.py,
# and by the tests that assert the whole binary set reaches the detectors.
set -uo pipefail

PATTERN='is_oss_binary|GENERIC_OSS_NAMES|oss_binaries_excluded|oss_excluded|_load_known_components|pattern\.oss|custom_functions'

hits=$(grep -rnE "$PATTERN" src/ tests/ --include=*.py || true)
if [ -n "$hits" ]; then
  echo "oss-exclusion gate FAILED: a retired scan-time exclusion identifier is back" >&2
  echo "$hits" >&2
  exit 1
fi
echo "✓ oss-exclusion: no scan-time binary exclusion identifiers"
