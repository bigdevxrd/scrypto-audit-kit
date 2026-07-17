#!/usr/bin/env python3
"""Example agent #1 — a free-tier pre-audit gate (no API key, no toolchain).

The smallest useful thing you can build on the kit: run the deterministic static analysis
over a Scrypto package and exit non-zero if anything lands at/above a severity threshold.
Drop it in CI, or call it from your own agent before spending a model call.

    python static_gate.py path/to/scrypto/package --fail-on high

Exits 0 if the package passes the gate, 1 if it fails, 2 on a usage error. With no path it
runs against the bundled deliberately-vulnerable fixture so you can see it work immediately.

This uses only the importable, stdlib-only core — `pip install scrypto-audit-kit` and it
runs anywhere, or run it straight from a clone (the import shim below handles both).
"""
import argparse
import os
import sys

# Run installed (pip install scrypto-audit-kit) OR straight from a clone.
try:
    from scrypto_audit_kit import sak_lib, static_analysis
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "bin"))
    import sak_lib  # type: ignore
    import static_analysis  # type: ignore

DEFAULT_PKG = os.path.join(os.path.dirname(__file__), "..", "vulnerable-vault")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("package", nargs="?", default=DEFAULT_PKG,
                    help="Scrypto package dir (defaults to the bundled fixture)")
    ap.add_argument("--fail-on", default="high",
                    help="none | low | medium | high | critical (default: high)")
    args = ap.parse_args()

    # 1. Deterministic static pass — reproducible, no model call.
    findings = static_analysis.analyze_package(args.package)

    # 2. Assemble a schema-shaped report and apply the severity gate (shared kit logic).
    report = sak_lib.build_report(findings)
    try:
        verdict = sak_lib.gate_verdict(report, args.fail_on)
    except ValueError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return 2

    # 3. Report, then gate.
    print(f"static pre-audit of {os.path.relpath(args.package)}: "
          f"{verdict['total']} finding(s) — {sak_lib.counts_summary(verdict['counts'])}")
    for f in findings:
        print(f"  [{f['severity']:>8}] {f['id']}  {f['location']}  —  {f['title']}")

    if not verdict["passed"]:
        print(f"\nFAIL: worst severity '{verdict['worst']}' is at/above the '{args.fail_on}' "
              f"threshold.", file=sys.stderr)
        return 1
    print(f"\nPASS: nothing at/above '{args.fail_on}'. (A pre-audit pass, not a human audit.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
