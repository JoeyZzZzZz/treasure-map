// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// Test-only (never shipped, never run by a scan). Reads or sets the session's no-return discovery
// analysis option, the one the promotion pass freezes while it recovers code and must then put back
// to the value it saved:
//   NoReturnOption.java report <label>   prints "NoReturnOption: <label> <value>", where <value> is
//                                        "true", "false" or "unset"
//   NoReturnOption.java set <value>      sets the option to <value> ("true" / "false")
// Run before and after the promotion pass, it shows whether that pass left the option as it found it.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;

public class NoReturnOption extends GhidraScript {
  // The analyzer option the promotion pass freezes (PromoteUndefined.NO_RETURN_OPTION).
  private static final String NO_RETURN_OPTION = "Non-Returning Functions - Discovered";

  @Override
  protected void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2) {
      throw new IllegalArgumentException("usage: NoReturnOption.java report <label> | set <value>");
    }
    if (args[0].equals("set")) {
      setAnalysisOption(currentProgram, NO_RETURN_OPTION, args[1]);
      return;
    }
    Options opts = currentProgram.getOptions("Analyzers");
    String value =
        opts.contains(NO_RETURN_OPTION)
            ? String.valueOf(opts.getBoolean(NO_RETURN_OPTION, false))
            : "unset";
    println("NoReturnOption: " + args[1] + " " + value);
  }
}
