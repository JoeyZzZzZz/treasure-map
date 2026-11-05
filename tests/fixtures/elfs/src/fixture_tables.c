/* Copyright (C) 2026 JoeyZzZzZz
 * SPDX-License-Identifier: Apache-2.0
 *
 * The dispatch-table fixture (a shared library): one {name -> handler} table the detector must
 * find, and record arrays that look like one and are not. Every name is synthetic.
 *
 *   commands      {name, internal function}           a table (5 records)
 *   builtins      {name, imported function}           a table (4 records)
 *   named_data    {name, pointer to a data object}    not a table: no handler is a function
 *   named_offsets {name, imported data object + 8*i}  not a table: each slot names a data object
 *                                                     with an addend, though its target lands on
 *                                                     an imported function (fixture_dep.c)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*handler_fn)(int);

__attribute__((noinline)) int fx_alpha(int x) { return x + 1; }
__attribute__((noinline)) int fx_beta(int x) { return x * 3; }
__attribute__((noinline)) int fx_gamma(int x) { return x - 7; }
__attribute__((noinline)) int fx_delta(int x) { return x ^ 0x55; }
__attribute__((noinline)) int fx_epsilon(int x) { return x << 2; }

struct command {
    const char *name;
    handler_fn fn;
};

const struct command commands[] = {
    {"alpha", fx_alpha},     {"beta", fx_beta},       {"gamma", fx_gamma},
    {"delta", fx_delta},     {"epsilon", fx_epsilon}, {NULL, NULL},
};

struct builtin {
    const char *name;
    const void *fn;
};

const struct builtin builtins[] = {
    {"print", (const void *)puts},   {"length", (const void *)strlen},
    {"compare", (const void *)strcmp}, {"lookup", (const void *)getenv},
    {NULL, NULL},
};

int fx_counters[8];

struct named {
    const char *name;
    const void *p;
};

const struct named named_data[] = {
    {"first", &fx_counters[0]}, {"second", &fx_counters[1]}, {"third", &fx_counters[2]},
    {"fourth", &fx_counters[3]}, {"fifth", &fx_counters[4]}, {NULL, NULL},
};

extern char fx_blob[];
extern int fx_ext_one(int), fx_ext_two(int), fx_ext_three(int), fx_ext_four(int);

const struct named named_offsets[] = {
    {"slot_one", fx_blob + 8},   {"slot_two", fx_blob + 16}, {"slot_three", fx_blob + 24},
    {"slot_four", fx_blob + 32}, {NULL, NULL},
};

int fx_imported(int x) {
    return fx_ext_one(x) + fx_ext_two(x) + fx_ext_three(x) + fx_ext_four(x);
}

int fx_dispatch(const char *name, int x) {
    for (const struct command *c = commands; c->name; c++) {
        if (strcmp(c->name, name) == 0) {
            return c->fn(x);
        }
    }
    return -1;
}
