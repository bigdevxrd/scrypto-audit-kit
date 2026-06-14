#!/usr/bin/env python3
"""Compatibility shim → ci_gate.main().

The gate logic lives in ci_gate.py (an importable, un-hyphenated module so it can back the
`sak-gate` console entry point). This hyphenated path is kept verbatim because the pre-audit
CI workflow (.github/workflows/pre-audit.yml), the docs, and tests/test_security.py invoke
`bin/ci-gate.py` directly — they all keep working unchanged.
"""
import sys

from ci_gate import main  # bin/ is sys.path[0] when this runs as a script

if __name__ == "__main__":
    sys.exit(main())
