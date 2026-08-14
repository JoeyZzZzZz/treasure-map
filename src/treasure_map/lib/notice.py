# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Legal / intended-use notice shown in the tool's main outputs.

A neutral reminder that the tool is for defensive auditing and research, that its output
is leads for review (not directly usable attack output), and that lawful use is the user's
responsibility. The substance mirrors the README's "Intended Use & Legal" section. No vendor
identity; not legal advice. Kept in its own module so callers reference only the constant.
"""

from __future__ import annotations

# Substance is fixed; layout/wording of the surrounding CLI text may vary.
LEGAL_NOTICE = (
    "Treasure Map is a defensive firmware-audit and vulnerability-research tool.\n"
    "Its output is analysis leads for human review — not exploits, payloads, or\n"
    "attack code. Use it only on firmware you lawfully possess and are authorized\n"
    "to analyze. Ensuring your use complies with the laws and license terms that\n"
    "apply to you is your responsibility."
)
