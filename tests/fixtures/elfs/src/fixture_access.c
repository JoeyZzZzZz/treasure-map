/* Copyright (C) 2026 JoeyZzZzZz
 * SPDX-License-Identifier: Apache-2.0
 *
 * The table-access fixture (a shared library): code that reads data tables in the shapes the
 * extractor's table-access observations describe. Every name is synthetic.
 *
 *   fx_dispatch_local    walks fx_ents: the key column goes to a local matcher (fx_match), not to a
 *                        str*cmp; the guard column is only tested; the handler column is called;
 *                        the record pointer escapes to fx_note
 *   fx_dispatch_nested   walks fx_groups, and inside a matched group walks the table its record
 *                        points to (a child table)
 *   fx_lookup            walks the table it is handed (a parameter); fx_dispatch_helper hands it
 *                        fx_more, a constant data address. fx_walk_unlinked walks a parameter no
 *                        call hands a constant address
 *   fx_call_hook         calls a function pointer read straight from data (no load expressed)
 *   fx_level_of          reads a plain global it does not call
 *   fx_count             walks fx_ents and calls and compares nothing
 *   fx_rotated           compares the first key before its loop, then in the loop steps the pointer
 *                        before comparing; both results are tested at the loop head, and on a
 *                        match the record's handler is called after the loop
 *   fx_deep_key          walks fx_live (a table the code may write, so its reads stay reads) and
 *                        hands the key it read first to strcmp only through four merges
 *   fx_many              calls 600 function pointers from one array: more rows than one function
 *                        keeps
 */
#include <string.h>

typedef void (*fx_fn)(void);

__attribute__((noinline)) void fx_on_a(void) { __asm__ volatile(""); }
__attribute__((noinline)) void fx_on_b(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void fx_on_c(void) { __asm__ volatile("nop; nop"); }

struct fx_ent {
    const char *name;
    int guard;
    fx_fn fn;
};

struct fx_group {
    const char *name;
    const struct fx_ent *ents;
};

const struct fx_ent fx_ents[] = {
    {"alpha", 1, fx_on_a},
    {"beta", 0, fx_on_b},
    {"gamma", 1, fx_on_c},
    {0, 0, 0},
};

const struct fx_ent fx_more[] = {
    {"delta", 1, fx_on_c},
    {"epsilon", 1, fx_on_a},
    {"zeta", 0, fx_on_b},
    {0, 0, 0},
};

const struct fx_group fx_groups[] = {
    {"first", fx_ents},
    {"second", fx_more},
    {0, 0},
};

__attribute__((noinline)) int fx_match(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

__attribute__((noinline)) void fx_note(const struct fx_ent *e) { __asm__ volatile("" ::"r"(e)); }

void fx_dispatch_local(const char *s) {
    for (const struct fx_ent *p = fx_ents; p->name; p++) {
        if (fx_match(p->name, s) && p->guard) {
            fx_note(p);
            p->fn();
            return;
        }
    }
}

void fx_dispatch_nested(const char *g, const char *s) {
    for (const struct fx_group *q = fx_groups; q->name; q++) {
        if (strcmp(q->name, g) != 0)
            continue;
        for (const struct fx_ent *p = q->ents; p->name; p++) {
            if (strcmp(p->name, s) == 0) {
                p->fn();
                return;
            }
        }
    }
}

__attribute__((noinline)) fx_fn fx_lookup(const struct fx_ent *tab, const char *s) {
    for (; tab->name; tab++)
        if (strcmp(tab->name, s) == 0)
            return tab->fn;
    return 0;
}

void fx_dispatch_helper(const char *s) {
    fx_fn f = fx_lookup(fx_more, s);
    if (f)
        f();
}

__attribute__((noinline)) int fx_walk_unlinked(const struct fx_ent *t) {
    int n = 0;
    for (; t->name; t++)
        n += t->guard;
    return n;
}

int fx_walk_caller(const struct fx_ent *t) { return fx_walk_unlinked(t + 1); }

fx_fn fx_hook = fx_on_b;
int fx_level = 3;

void fx_call_hook(void) { fx_hook(); }

int fx_level_of(void) { return fx_level + 1; }

int fx_count(void) {
    int n = 0;
    for (const struct fx_ent *p = fx_ents; p->name; p++)
        n++;
    return n;
}

/* Built without optimisation, so the compiler keeps the one test at the loop head that both
 * comparisons' results reach (optimised, it copies the test into the loop). */
__attribute__((optimize("O0"))) void fx_rotated(const char *s) {
    const struct fx_ent *p = fx_more;
    int r = strcmp(p->name, s);
    for (;;) {
        if (r == 0)
            break;
        p++;
        if (!p->name)
            return;
        r = strcmp(p->name, s);
    }
    p->fn();
}

struct fx_ent fx_live[] = {
    {"eta", 1, fx_on_a},
    {"theta", 0, fx_on_b},
    {0, 0, 0},
};

/* Built without optimisation, so each `if` that may read the key again leaves a merge of the
 * variable behind: the key read first reaches strcmp through four of them. */
__attribute__((optimize("O0"))) fx_fn fx_deep_key(const char *s, int a, int b, int c, int d) {
    for (const struct fx_ent *p = fx_live; p->name; p++) {
        const char *k = p->name;
        if (a)
            k = p->name;
        if (b)
            k = p->name;
        if (c)
            k = p->name;
        if (d)
            k = p->name;
        if (strcmp(k, s) == 0)
            return p->fn;
    }
    return 0;
}

fx_fn fx_fns[600] = {[0 ... 599] = fx_on_a};

#define FX_CALL(i) fx_fns[i]();
#define FX_CALL10(b) \
    FX_CALL((b) + 0) FX_CALL((b) + 1) FX_CALL((b) + 2) FX_CALL((b) + 3) FX_CALL((b) + 4) \
        FX_CALL((b) + 5) FX_CALL((b) + 6) FX_CALL((b) + 7) FX_CALL((b) + 8) FX_CALL((b) + 9)
#define FX_CALL100(b) \
    FX_CALL10((b) + 0) FX_CALL10((b) + 10) FX_CALL10((b) + 20) FX_CALL10((b) + 30) \
        FX_CALL10((b) + 40) FX_CALL10((b) + 50) FX_CALL10((b) + 60) FX_CALL10((b) + 70) \
            FX_CALL10((b) + 80) FX_CALL10((b) + 90)

void fx_many(void) {
    FX_CALL100(0) FX_CALL100(100) FX_CALL100(200) FX_CALL100(300) FX_CALL100(400) FX_CALL100(500)
}
