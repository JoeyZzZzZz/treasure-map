# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0

__version__ = "0.1.0"

# The explicit "we could not confirm which version produced this" sentinel for any recorded
# analysis-tool version. It is a VALUE, never None: a missing/undetectable version must stay
# visible and be read conservatively (cannot-confirm-same is not confirmed-same), and a None
# would instead let a comparison short-circuit into a silent "no skew".
UNKNOWN_VERSION = "unknown"
