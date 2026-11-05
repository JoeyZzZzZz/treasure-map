#!/bin/sh
# Rebuild the ELF fixtures from the sources in src/. All are written for this repository and carry
# its license (Apache-2.0); see PROVENANCE.md. Run from anywhere: paths are script-relative.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
gcc -O1 -o exe_x86_64 src/fixture_exe.c
gcc -O1 -fPIC -shared -Wl,-soname,libfixture.so -o libfixture_x86_64.so src/fixture_lib.c

# The dispatch-table fixtures. libfxdep.so exists only to give libtables_x86_64.so its imports; it
# is linked against, not committed.
dep="$(mktemp -d)"
trap 'rm -rf "$dep"' EXIT
gcc -O1 -fPIC -shared -Wl,-soname,libfxdep.so -o "$dep/libfxdep.so" src/fixture_dep.c
gcc -O1 -fPIC -shared -Wl,-soname,libtables.so -o libtables_x86_64.so src/fixture_tables.c \
    -L"$dep" -lfxdep
g++ -O1 -fPIC -shared -Wl,-soname,libclasses.so -o libclasses_x86_64.so src/fixture_classes.cc

# The code-recovery fixture: its layout is the source order, and three of its parts are named by
# nothing once their symbols are stripped.
gcc -O1 -fno-toplevel-reorder -no-pie -o promote_x86_64 src/fixture_promote.c
objcopy --strip-symbol=fx_garbage --strip-symbol=fx_hidden --strip-symbol=fx_small promote_x86_64
