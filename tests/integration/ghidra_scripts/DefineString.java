// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// Test-only (never shipped, never run by a scan). Defines a fixed-length string with no terminator
// over the first occurrence of some bytes in the program:
//   DefineString.java <bytes-hex> <length>
// finds the first address holding <bytes-hex> (e.g. 677265656e01 for "green\x01") and defines an
// ASCII string of <length> bytes there (5 for "green"), clearing whatever was defined over it.
// This makes a key Ghidra defines as a string although its bytes do not end in a NUL.
//
// Prints "DefineString: defined <length> bytes at <address>", or "DefineString: no <bytes-hex>"
// when the bytes occur nowhere, so the test can tell the setup held.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class DefineString extends GhidraScript {
  @Override
  protected void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2 || args[0].length() % 2 != 0) {
      throw new IllegalArgumentException("usage: DefineString.java <bytes-hex> <length>");
    }
    byte[] pattern = new byte[args[0].length() / 2];
    for (int i = 0; i < pattern.length; i++) {
      pattern[i] = (byte) Integer.parseInt(args[0].substring(2 * i, 2 * i + 2), 16);
    }
    int length = Integer.parseInt(args[1]);
    Address at = find(currentProgram.getMinAddress(), pattern);
    if (at == null) {
      println("DefineString: no " + args[0]);
      return;
    }
    clearListing(at, at.add(length - 1));
    createAsciiString(at, length);
    println("DefineString: defined " + length + " bytes at " + at);
  }
}
