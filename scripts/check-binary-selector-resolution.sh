#!/usr/bin/env bash
# One resolver for "which binary did the caller mean".
#
# A short name is a LABEL, not an identity: one firmware ships two files called libstdc++.so.6
# under different roots, with different content and different function tables. Any query that
# selects a binary by name and takes what comes back is answering about whichever row the database
# returned — silently, and possibly differently for two queries over the same firmware.
#
# So selector resolution lives in ONE module (lib/binary_id.py), which checks every tier for
# multiples and REFUSES with the candidates rather than picking. This gate keeps it that way: it
# fails when a by-name binary lookup reappears anywhere else.
#
# SCOPE, stated so the gate is not mistaken for a proof: it matches the SQL SHAPE of a by-name
# lookup. It cannot see a lookup assembled at runtime, and it deliberately does not flag
# `b.path = ?` — the honest resolvers use that form too, and what separates them is whether the
# result is fetchall-ed and checked for multiples, which no regex can see.
set -uo pipefail

PATTERN='FROM (binaries|current_binaries) WHERE (name|path) = \?|b\.name = \? OR b\.sha256|binaries.*LIMIT 1'

hits=$(grep -rnE "$PATTERN" src/ --include=*.py --exclude=binary_id.py || true)
if [ -n "$hits" ]; then
  echo "binary-selector gate FAILED: a by-name binary lookup outside lib/binary_id.py" >&2
  echo "$hits" >&2
  echo "" >&2
  echo "Resolve through resolve_binary() / resolve_binary_in_db(), which refuse an ambiguous" >&2
  echo "selector with its candidates instead of returning one of several rows." >&2
  exit 1
fi
echo "✓ binary-selector: every by-name binary lookup goes through lib/binary_id.py"
