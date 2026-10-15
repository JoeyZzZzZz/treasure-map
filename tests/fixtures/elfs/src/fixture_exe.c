/* Copyright (C) 2026 JoeyZzZzZz
 * SPDX-License-Identifier: Apache-2.0
 *
 * A minimal dynamically linked executable: the ELF-inventory fixture (architecture, ELF type,
 * DT_NEEDED, loadable segments). It does nothing of interest at run time on purpose.
 */
#include <stdio.h>
#include <string.h>

static const char VERSION_TEXT[] = "fixture 1.0";

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        puts(VERSION_TEXT);
        return 0;
    }
    return argc > 2 ? 1 : 0;
}
