# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The one operand-markup failure the export builder renders around (lib/diff/ghidra/
StackVarnodeMarkup.java), decided from the exception alone: compiled and run with the JDK only.

Real Ghidra raises it from VariableStorage.getStackOffset; a test cannot make Ghidra raise any
other UnsupportedOperationException message there, so the decision is checked at the judge itself:
the exact message from a getStackOffset frame is that failure, and every near miss is not (it must
propagate and fail the export loudly).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from treasure_map.lib.export_stamp import EXPORT_SCRIPT_DIR, MARKUP_JUDGE

no_jdk = shutil.which("javac") is None or shutil.which("java") is None

_HARNESS = r"""
public class JudgeHarness {
  static UnsupportedOperationException raisedBy(String method, String msg) {
    UnsupportedOperationException e = new UnsupportedOperationException(msg);
    e.setStackTrace(new StackTraceElement[] {
        new StackTraceElement("ghidra.program.model.listing.VariableStorage", method, "x", 1),
        new StackTraceElement("ghidra.app.util.Other", "render", "y", 2)});
    return e;
  }

  public static void main(String[] args) {
    String m = StackVarnodeMarkup.MESSAGE;
    System.out.println("target=" + StackVarnodeMarkup.isFailure(raisedBy("getStackOffset", m)));
    System.out.println("other_message="
        + StackVarnodeMarkup.isFailure(raisedBy("getStackOffset", m + ".")));
    System.out.println("null_message="
        + StackVarnodeMarkup.isFailure(raisedBy("getStackOffset", null)));
    System.out.println("other_frame=" + StackVarnodeMarkup.isFailure(raisedBy("getOffset", m)));
    IllegalStateException wrongType = new IllegalStateException(m);
    wrongType.setStackTrace(raisedBy("getStackOffset", m).getStackTrace());
    System.out.println("other_type=" + StackVarnodeMarkup.isFailure(wrongType));
  }
}
"""


@pytest.mark.skipif(no_jdk, reason="no JDK (javac / java) on PATH")
def test_the_judge_accepts_only_the_stack_varnode_failure(tmp_path: Path) -> None:
    """★ True for an UnsupportedOperationException carrying exactly the message, from a
    getStackOffset frame; false for another message, no message, another frame or another type.

    MUTATION (verified RED): drop the frame check -> other_frame reads true -> RED; match the
    message by prefix -> other_message reads true -> RED."""
    shutil.copy(EXPORT_SCRIPT_DIR / MARKUP_JUDGE, tmp_path / MARKUP_JUDGE)
    (tmp_path / "JudgeHarness.java").write_text(_HARNESS, encoding="utf-8")
    subprocess.run(
        [
            "javac",
            "-d",
            str(tmp_path),
            str(tmp_path / MARKUP_JUDGE),
            str(tmp_path / "JudgeHarness.java"),
        ],
        check=True,
        capture_output=True,
    )
    out = subprocess.run(
        ["java", "-cp", str(tmp_path), "JudgeHarness"], check=True, capture_output=True, text=True
    ).stdout
    got = dict(line.split("=", 1) for line in out.split())
    assert got == {
        "target": "true",
        "other_message": "false",
        "null_message": "false",
        "other_frame": "false",
        "other_type": "false",
    }
