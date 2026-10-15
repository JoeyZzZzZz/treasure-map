#!/bin/sh
# Rebuild the two ELF fixtures from the sources in src/. Both are written for this repository and
# carry its license (Apache-2.0); see PROVENANCE.md. Run from anywhere: paths are script-relative.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
gcc -O1 -o exe_x86_64 src/fixture_exe.c
gcc -O1 -fPIC -shared -Wl,-soname,libfixture.so -o libfixture_x86_64.so src/fixture_lib.c
