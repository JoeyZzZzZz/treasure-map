/* Copyright (C) 2026 JoeyZzZzZz
 * SPDX-License-Identifier: Apache-2.0
 *
 * A small shared library: the ELF-export / BinExport fixture. It exports well over fifty
 * functions and imports a handful from libc, so a reader can tell a binary's exports from its
 * imports. The bodies are deliberately ordinary — loops, copies, formatting — so a decompiler
 * recovers real functions from them.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A running checksum over a byte buffer (two 16-bit sums, the usual shape). */
unsigned long fx_checksum(unsigned long seed, const unsigned char *buf, size_t len) {
    unsigned long a = seed & 0xffff, b = (seed >> 16) & 0xffff;
    for (size_t i = 0; i < len; i++) {
        a = (a + buf[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

/* Copy at most cap-1 bytes and terminate; returns the bytes copied. */
size_t fx_pack(char *dst, size_t cap, const char *src) {
    if (cap == 0) {
        return 0;
    }
    size_t n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
    return n;
}

/* Format a key/value line into a caller buffer. */
int fx_format(char *out, size_t cap, const char *key, long value) {
    return snprintf(out, cap, "%s=%ld\n", key, value);
}

/* A heap copy the caller frees. */
char *fx_dup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p != NULL) {
        memcpy(p, s, n);
    }
    return p;
}

/* Fifty-six small, distinct exported transforms. Each differs in its constants, so none folds
 * into another. */
#define FX_OP(n)                                                         \
    int fx_op_##n(const char *s, char *out, size_t cap) {                \
        size_t len = strlen(s);                                          \
        size_t i = 0;                                                    \
        for (; i < len && i + 1 < cap; i++) {                            \
            out[i] = (char)((s[i] ^ (0x11 * (n))) + (n));                \
        }                                                                \
        if (cap > 0) {                                                   \
            out[i < cap ? i : cap - 1] = '\0';                           \
        }                                                                \
        return (int)(i * (n) % 97);                                      \
    }

FX_OP(1) FX_OP(2) FX_OP(3) FX_OP(4) FX_OP(5) FX_OP(6) FX_OP(7) FX_OP(8)
FX_OP(9) FX_OP(10) FX_OP(11) FX_OP(12) FX_OP(13) FX_OP(14) FX_OP(15) FX_OP(16)
FX_OP(17) FX_OP(18) FX_OP(19) FX_OP(20) FX_OP(21) FX_OP(22) FX_OP(23) FX_OP(24)
FX_OP(25) FX_OP(26) FX_OP(27) FX_OP(28) FX_OP(29) FX_OP(30) FX_OP(31) FX_OP(32)
FX_OP(33) FX_OP(34) FX_OP(35) FX_OP(36) FX_OP(37) FX_OP(38) FX_OP(39) FX_OP(40)
FX_OP(41) FX_OP(42) FX_OP(43) FX_OP(44) FX_OP(45) FX_OP(46) FX_OP(47) FX_OP(48)
FX_OP(49) FX_OP(50) FX_OP(51) FX_OP(52) FX_OP(53) FX_OP(54) FX_OP(55) FX_OP(56)
