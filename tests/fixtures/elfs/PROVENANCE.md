# ELF fixtures

Both binaries here are built from the sources in `src/`, which were written for this repository and
carry its license (Apache-2.0). No third-party code is compiled into them beyond the C runtime
start-up objects every dynamically linked program carries.

| File | Source | What the tests read from it |
|---|---|---|
| `exe_x86_64` | `src/fixture_exe.c` | a dynamically linked x86-64 PIE: architecture, ELF type, `DT_NEEDED` (libc), loadable segments |
| `libfixture_x86_64.so` | `src/fixture_lib.c` | a shared object exporting 60 functions and importing a few from libc: the dynamic export table, code presence, a BinExport smoke run |

Rebuild with `./build.sh` (gcc, x86-64 Linux). The committed files were built with gcc 13.3.0 and
GNU ld 2.42. A different compiler produces different bytes and addresses; the tests assert
properties (export names and counts, types, dependencies), not offsets, so a rebuild should keep
them green.
