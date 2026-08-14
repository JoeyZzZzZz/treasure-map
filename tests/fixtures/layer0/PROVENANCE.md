# layer-0 fixture provenance

`shapes_before_vs_shapes_after.BinDiff` is **real BinDiff output over a synthetic subject.**

| | |
|---|---|
| Subject | `src/shapes_before.c` and `src/shapes_after.c`, written for this repository |
| Derived from firmware or third-party binaries | **No** |
| Produced by | gcc → strip → Ghidra + BinExport → `bindiff` CLI |
| Regenerate with | `tests/fixtures/layer0/make_fixture.sh` |

## Why real tool output rather than a crafted SQLite file

The tests that read it check how the parse handles what BinDiff actually emits. A hand-built table
would only ever confirm our own reading of the format, so a wrong assumption about it would pass.
The two C variants are shaped to contain the cases the parse has to get right — a block of
identical stripped functions BinDiff cannot tell apart, functions that genuinely change, and
functions that do not — but the confidences, similarities and pairings in the file are BinDiff's,
not ours.

## Why the sources are built stripped

An unstripped build hands BinDiff distinct symbol names, which it matches on, and every pair comes
back at high confidence. Stripping removes that shortcut and leaves it the structural evidence it
has on a real firmware binary. That is what produces the pairs at similarity 1.0 with a confidence
below the alignment threshold — the case proving alignment must follow confidence, not similarity.

## Regeneration is not bit-reproducible

The script needs the real toolchain (Ghidra 11.4.3 + BinExport + BinDiff 8 + gcc), so it does not
run in CI. A different toolchain will produce different addresses and confidences, which moves the
counts the fingerprint tests assert. Those tests describe the COMMITTED file. If you regenerate,
expect to update them, and check the shapes above still exist before you do.

## What this fixture cannot show

The previous fixture was a diff of a real firmware library, so it also evidenced that the parse
copes with production-scale input: about 1800 matched pairs against 48 here. That evidence is gone
along with the firmware-derived data, deliberately. Scale behaviour is not covered by these tests.
