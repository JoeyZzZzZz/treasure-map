/* Synthetic diff subject — variant B ("after").
 *
 * NOT derived from any firmware or third-party binary. Written for this repository so that a real
 * BinDiff run over the two variants contains the shapes the layer-0 parse tests need:
 *
 *   * a block of structurally IDENTICAL, NAME-FREE small functions. They are static and the
 *     library is stripped, so BinDiff sees several functions it cannot tell apart: it pairs them
 *     at similarity 1.0 while reporting a confidence far below the alignment threshold. That
 *     combination is the case proving the parse must align on confidence and never on similarity.
 *     Stripped, structurally-repetitive code is the normal shape of the firmware this tool reads.
 *   * functions whose body differs between the two variants (similarity below 1.0).
 *   * exported, individually distinguishable functions that do not change (high confidence).
 *
 * Build both variants with tests/fixtures/layer0/make_fixture.sh.
 */
#include <stdlib.h>
#include <string.h>

/* --- identical, static, name-free after strip: the pairing ambiguity lives here --- */
#define WRAPPER(n) static int wrap_##n(int a, int b) { return (a * 3) + (b << 2) - 7; }
WRAPPER(00) WRAPPER(01) WRAPPER(02) WRAPPER(03) WRAPPER(04)
WRAPPER(05) WRAPPER(06) WRAPPER(07) WRAPPER(08) WRAPPER(09)
WRAPPER(10) WRAPPER(11) WRAPPER(12) WRAPPER(13) WRAPPER(14)
WRAPPER(15) WRAPPER(16) WRAPPER(17) WRAPPER(18) WRAPPER(19)

typedef int (*wrap_fn)(int, int);

/* A table keeps every wrapper referenced, so -O1 cannot discard them as unused. Going through a
   function pointer also stops them being inlined into the dispatcher. */
static wrap_fn const TABLE[] = {
    wrap_00, wrap_01, wrap_02, wrap_03, wrap_04, wrap_05, wrap_06, wrap_07, wrap_08, wrap_09,
    wrap_10, wrap_11, wrap_12, wrap_13, wrap_14, wrap_15, wrap_16, wrap_17, wrap_18, wrap_19,
};

int dispatch(int which, int a, int b) {
    if (which < 0 || which >= (int)(sizeof(TABLE) / sizeof(TABLE[0]))) return -1;
    return TABLE[which](a, b);
}

/* --- distinguishable, unchanged across variants --- */
int stable_sum(const int *v, int n) {
    int t = 0;
    for (int i = 0; i < n; i++) { if (v[i] > 0) t += v[i]; else t -= v[i]; }
    return t;
}

char *stable_dup(const char *s) {
    size_t n = strlen(s);
    char *out = malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n + 1);
    return out;
}

int stable_classify(int x) {
    if (x < 0) return -1;
    if (x == 0) return 0;
    if (x < 10) return 1;
    if (x < 100) return 2;
    return 3;
}

/* --- changed between the variants --- */
int changed_scale(int x) { if (x < 0) return -x * 3; return x * 3 + 7; }

int changed_walk(const int *v, int n) {
    int t = 0;
    for (int i = 0; i < n; i++) { if (v[i] & 1) t += v[i] * 2; else t += v[i]; }
    return t;
}
