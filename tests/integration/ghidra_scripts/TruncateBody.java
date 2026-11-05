// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// Test-only (never shipped, never run by a scan). Shrinks the body of each function named in the
// script arguments to its first instruction, so the rest of that function's code is in no function
// while its entry still holds one. Run before the promotion pass, this puts the pass in front of a
// block whose function entry already exists — createFunction then returns that existing function,
// which the pass must neither count as created nor mark as promoted.
//
// Prints one line per function it truncated ("TruncateBody: truncated <name> at <entry> to <n>
// bytes"), and one naming each argument no function carries, so the test can tell the setup held.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class TruncateBody extends GhidraScript {
  @Override
  protected void run() throws Exception {
    for (String name : getScriptArgs()) {
      boolean found = false;
      for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        if (!f.getName().equals(name)) {
          continue;
        }
        Instruction first = getInstructionAt(f.getEntryPoint());
        if (first == null) {
          continue;
        }
        f.setBody(new AddressSet(first.getMinAddress(), first.getMaxAddress()));
        found = true;
        println("TruncateBody: truncated " + name + " at " + f.getEntryPoint() + " to "
            + f.getBody().getNumAddresses() + " bytes");
      }
      if (!found) {
        println("TruncateBody: no function " + name);
      }
    }
  }
}
