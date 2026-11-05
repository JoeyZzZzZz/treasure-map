/* Copyright (C) 2026 JoeyZzZzZz
 * SPDX-License-Identifier: Apache-2.0
 *
 * The code-recovery fixture (x86-64 executable, built with -fno-toplevel-reorder so the layout
 * below is the layout in .text). build.sh strips the symbols of fx_garbage, fx_hidden and fx_small
 * so nothing names them: only data pointers lead to the first two, and nothing to the third. Each
 * part is something the extraction's promotion / recovery pass meets in firmware; every name is
 * synthetic.
 *
 *   fx_blob        32 bytes of data inside .text that nothing executes (an undefined range).
 *   fx_small       8 bytes between two functions that nothing executes or points at (an
 *                  undefined range below the recorded minimum).
 *   fx_garbage     two instructions, then bytes that do not decode on x86-64, reached only
 *                  through a data pointer (the decode yields something, and raises errors).
 *   fx_hidden      a function reached only through a data pointer.
 *   puts           an import: its PLT stub is a thunk.
 */
#include <stdio.h>

__attribute__((noinline)) int fx_first(int x) {
    puts("first");
    return x * 7 + 3;
}

__asm__(".text\n"
        ".globl fx_blob\n"
        "fx_blob:\n"
        ".byte 0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50\n"
        ".byte 0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x61,0x62,0x63,0x64,0x65,0x66\n"
        ".globl fx_garbage\n"
        "fx_garbage:\n"
        ".byte 0x90,0x90,0x06,0x06,0x06,0x06,0x06,0x06\n"
        ".p2align 4\n"
        ".globl fx_hidden\n"
        "fx_hidden:\n"
        "  movl $42, %eax\n"
        "  ret\n");

extern char fx_garbage[], fx_hidden[];
void *const fx_pointers[] = {fx_garbage, fx_hidden};

__attribute__((noinline)) int fx_last(int x) { return x + (int)(long)fx_pointers[x & 1]; }

__asm__(".text\n"
        ".globl fx_small\n"
        "fx_small:\n"
        ".byte 0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x06\n");

int main(int argc, char **argv) {
    (void)argv;
    return fx_first(argc) + fx_last(argc);
}
