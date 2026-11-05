/* Copyright (C) 2026 JoeyZzZzZz
 * SPDX-License-Identifier: Apache-2.0
 *
 * The library fixture_tables.c imports from: one data object, then four functions. In the
 * importer's external layout the four functions sit right after the object, so "the object + 8*i"
 * lands on each of them in turn (the shape the dispatch-table check refuses). Synthetic names.
 */
char fx_blob[64];
int fx_ext_one(int x) { return x + 11; }
int fx_ext_two(int x) { return x + 22; }
int fx_ext_three(int x) { return x + 33; }
int fx_ext_four(int x) { return x + 44; }
