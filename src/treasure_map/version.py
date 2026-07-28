# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only

__version__ = "0.0.1"

# The explicit "we could not confirm which version produced this" sentinel for any recorded
# analysis-tool version. It is a VALUE, never None: a missing/undetectable version must stay
# visible and be read conservatively (cannot-confirm-same is not confirmed-same), and a None
# would instead let a comparison short-circuit into a silent "no skew".
UNKNOWN_VERSION = "unknown"
