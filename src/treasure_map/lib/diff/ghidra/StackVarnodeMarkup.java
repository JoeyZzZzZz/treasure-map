// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// The one operand-markup failure the export builder renders around, decided from the exception
// alone. Ghidra throws it while marking up an operand that references a variable whose storage
// starts on the stack but does not end there (a composite such as Stack[0x0]:4,r3:4): the variable
// reads as a stack variable, and its stack offset cannot be computed.
//
// Kept in its own file with no import beyond the JDK, so its decision can be compiled and tested
// without Ghidra or the BinExport extension. Part of the export, hashed with the export scripts.

public final class StackVarnodeMarkup {

  /** The message Ghidra's VariableStorage.getStackOffset throws with. */
  public static final String MESSAGE = "Storage does not have a stack varnode";

  private StackVarnodeMarkup() {}

  /**
   * True only for that failure: an UnsupportedOperationException carrying exactly that message,
   * raised (somewhere on its stack) from a getStackOffset frame. Any other exception, message or
   * stack is something else and must propagate.
   */
  public static boolean isFailure(Throwable e) {
    if (!(e instanceof UnsupportedOperationException)) {
      return false;
    }
    if (!MESSAGE.equals(e.getMessage())) {
      return false;
    }
    for (StackTraceElement frame : e.getStackTrace()) {
      if ("getStackOffset".equals(frame.getMethodName())) {
        return true;
      }
    }
    return false;
  }
}
