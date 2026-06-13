#!/usr/bin/env python3
"""CI gate: fail the build when a pre-audit report has findings at/above a severity.

Reads a report.json (or every *.json in a directory) and exits non-zero when any
finding's severity is >= --fail-on. Use it in CI to block a PR on Critical/High
pre-audit findings, and to back an honest "pre-audit passing" badge. Stdlib only.
"""
import argparse
import glob
import json
import os
import sys

RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
ORDER = ["critical", "high", "medium", "low", "info"]


def load_reports(path):
    if os.path.isdir(path):
        return sorted(glob.glob(os.path.join(path, "*.json")))
    return [path] if os.path.exists(path) else []


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reports", required=True, help="a report.json file or a directory of them")
    ap.add_argument("--fail-on", default="high", help="none | critical | high | medium | low (default: high)")
    args = ap.parse_args()

    fail_on = args.fail_on.lower()
    if fail_on == "none":
        threshold = 99  # never fails
    elif fail_on in RANK:
        threshold = RANK[fail_on]
    else:
        print(f"error: --fail-on must be none|critical|high|medium|low (got {args.fail_on!r})", file=sys.stderr)
        return 2

    files = load_reports(args.reports)
    if not files:
        print(f"warn: no report.json found at {args.reports} — nothing to gate", file=sys.stderr)
        return 0

    counts, worst, total = {}, 0, 0
    for fp in files:
        try:
            with open(fp, encoding="utf-8") as fh:
                report = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warn: skipping unreadable {fp}: {exc}", file=sys.stderr)
            continue
        for finding in report.get("findings", []):
            sev = str(finding.get("severity", "")).lower()
            counts[sev] = counts.get(sev, 0) + 1
            total += 1
            worst = max(worst, RANK.get(sev, 0))

    summary = ", ".join(f"{counts[s]} {s}" for s in ORDER if counts.get(s)) or "none"
    print(f"pre-audit gate: {total} findings ({summary}); threshold = {fail_on}")

    if worst >= threshold:
        worst_label = next(k for k, v in RANK.items() if v == worst)
        print(f"::error::pre-audit gate failed — found {worst_label} finding(s) at or above '{fail_on}'")
        return 1
    print("pre-audit gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
