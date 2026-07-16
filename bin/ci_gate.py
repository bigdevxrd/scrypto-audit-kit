#!/usr/bin/env python3
"""CI gate: fail the build when a pre-audit report has findings at/above a severity.

Reads a report.json (or every *.json in a directory) and exits non-zero when any
finding's severity is >= --fail-on. Backs an honest "pre-audit passing" badge.
Stdlib only; shares its logic with the MCP server via sak_lib.

This is the importable, un-hyphenated home of the gate CLI (it backs the `sak-gate`
console entry point). The historical `bin/ci-gate.py` is a thin shim that calls main()
here, so existing invocations (the pre-audit CI workflow, tests) keep working.
"""
import argparse
import sys

import sak_lib


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reports", required=True, help="a report.json file or a directory of them")
    ap.add_argument("--fail-on", default="high", help="none | critical | high | medium | low (default: high)")
    ap.add_argument("--allow-missing", action="store_true",
                    help="pass when no report is found (default: fail closed)")
    args = ap.parse_args()

    # Fail CLOSED: a missing, unreadable, or malformed report must not pass the gate.
    # Shares sak_lib.collect_findings with the MCP gate so both surfaces fail closed identically.
    try:
        findings = sak_lib.collect_findings(args.reports, allow_missing=args.allow_missing)
    except sak_lib.GateError as exc:
        print(f"::error::{exc} — failing closed (use --allow-missing to opt out)", file=sys.stderr)
        return 1
    if findings is None:
        print(f"warn: no report.json at {args.reports} — passing (--allow-missing)", file=sys.stderr)
        return 0

    try:
        verdict = sak_lib.gate_verdict({"findings": findings}, args.fail_on)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"pre-audit gate: {verdict['total']} findings "
          f"({sak_lib.counts_summary(verdict['counts'])}); threshold = {verdict['fail_on']}")
    if not verdict["passed"]:
        print(f"::error::pre-audit gate failed — found {verdict['worst']} finding(s) "
              f"at or above '{verdict['fail_on']}'")
        return 1
    print("pre-audit gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
