#!/usr/bin/env python3
"""CI gate: fail the build when a pre-audit report has findings at/above a severity.

Reads a report.json (or every *.json in a directory) and exits non-zero when any
finding's severity is >= --fail-on. Backs an honest "pre-audit passing" badge.
Stdlib only; shares its logic with the MCP server via sak_lib.
"""
import argparse
import sys

import sak_lib


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reports", required=True, help="a report.json file or a directory of them")
    ap.add_argument("--fail-on", default="high", help="none | critical | high | medium | low (default: high)")
    args = ap.parse_args()

    files = sak_lib.find_reports(args.reports)
    if not files:
        print(f"warn: no report.json found at {args.reports} — nothing to gate", file=sys.stderr)
        return 0

    findings = []
    for fp in files:
        try:
            findings.extend(sak_lib.load_report(fp).get("findings", []))
        except (OSError, ValueError) as exc:  # ValueError covers JSONDecodeError
            print(f"warn: skipping unreadable {fp}: {exc}", file=sys.stderr)

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
