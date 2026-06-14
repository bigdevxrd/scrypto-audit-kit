#!/usr/bin/env python3
"""Example agent #2 — the audit -> fix -> verify loop, end to end.

This is the loop an agent runs to help a user harden a blueprint, using the SAME functions
the MCP server exposes (so the shape is identical whether you call them in-process, like
here, or over MCP, like example #3):

    1. static_scan(pkg)                 — free triage, no model call
    2. audit_package(pkg)               — semantic findings              [needs ANTHROPIC_API_KEY]
    3. show_finding_source(...)         — verify each High/Critical citation is real
    4. <you apply a minimal fix>        — the kit is READ-ONLY; the agent + user own edits
    5. reaudit_diff(pkg, baseline)      — confirm what closed, nothing new regressed   [LLM]
    6. gate(report, "high")             — pass/fail, honestly a pre-audit not an audit
    7. attestation_payload(report)      — optional L3: bind the run to an on-chain record

Run it with no ANTHROPIC_API_KEY and it walks the deterministic half of the loop (1, the
citation-verify mechanic of 3, 6, 7) over the bundled fixture, and narrates the model steps
it would otherwise run. With a key and a kit clone, it runs the whole thing.

    python audit_fix_verify.py [path/to/scrypto/package]
"""
import json
import os
import sys
import tempfile

# Run installed OR from a clone. The MCP tool functions live in mcp_server (import-safe).
try:
    from scrypto_audit_kit import mcp_server, sak_lib
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "bin"))
    import mcp_server  # type: ignore
    import sak_lib  # type: ignore

DEFAULT_PKG = os.path.join(os.path.dirname(__file__), "..", "vulnerable-vault")


def _heading(n, text):
    print(f"\n=== {n}. {text} ===")


def main():
    pkg = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PKG
    have_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    print(f"audit -> fix -> verify loop over {os.path.relpath(pkg)}")
    print(f"ANTHROPIC_API_KEY: {'set — running the full loop' if have_key else 'unset — running the free-tier walkthrough'}")

    # 1. Static triage — always free.
    _heading(1, "static_scan (free)")
    static = mcp_server.static_scan(pkg)
    print(f"{static['count']} static finding(s): {sak_lib.counts_summary(static['counts'])}")

    # 2. Full pre-audit (LLM) — or fall back to a static-only report we can drive the rest with.
    if have_key:
        _heading(2, "audit_package (LLM semantic pass)")
        report = mcp_server.audit_package(pkg)
        if "error" in report:
            print(f"audit failed: {report['error']}", file=sys.stderr)
            return 0
        report_path = report["report_path"]
    else:
        _heading(2, "audit_package — SKIPPED (no key); driving the rest from the static report")
        report_path = os.path.join(tempfile.mkdtemp(prefix="sak-demo-"), "report.json")
        demo_report = sak_lib.build_report(static["findings"])
        demo_report["kit"]["model"] = "static-only"  # the harness stamps provenance; mirror it so the level is honest
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(demo_report, fh, indent=2)
    print(f"report.json -> {report_path}")

    # 3. Verify each High/Critical citation before acting — the model (or a rule) can mis-cite.
    _heading(3, "show_finding_source — verify the worst citations are real")
    worst = mcp_server.get_findings(report_path, severity_min="high")
    if not worst["findings"]:
        print("no High/Critical findings to verify (at this tier).")
    for f in worst["findings"]:
        shown = mcp_server.show_finding_source(report_path, f["id"], pkg, context=2)
        src = shown.get("source", {})
        first_line = (src.get("snippet", "").splitlines() or [src.get("error", "?")])[0]
        print(f"  {f['id']} {f['location']} — {f.get('title', '')}")
        print(f"      cited code: {first_line.strip()}")

    # 4. Apply a minimal fix. The kit never edits code under review — this is where YOUR
    #    agent proposes a patch and the user approves it. (Nothing is edited in this demo.)
    _heading(4, "apply a minimal fix — read-only kit; agent + user own the edit (skipped in demo)")

    # 5. Re-verify after the fix. Needs another model pass, so it's narrated when key-less.
    _heading(5, "reaudit_diff — confirm fixed / still_open / new")
    if have_key:
        diff = mcp_server.reaudit_diff(pkg, report_path)
        print(f"  {diff.get('summary', diff)}")
    else:
        print("  would re-run the audit and diff against the baseline report by finding signature.")

    # 6. Gate — the honest pass/fail.
    _heading(6, "gate (fail_on=high)")
    verdict = mcp_server.gate(report_path, "high")
    print(f"  passed={verdict['passed']} worst={verdict['worst']} "
          f"counts=({sak_lib.counts_summary(verdict['counts'])})")

    # 7. Optional L3 — bind this run to an on-chain attestation payload.
    _heading(7, "attestation_payload (optional, free) — the L3 bridge")
    payload = mcp_server.attestation_payload(report_path)["payload"]
    note = " (empty: a raw static report isn't provenance-stamped; ./audit.sh stamps source_hash)"
    print(f"  level={payload['level']} source_hash={payload['source_hash'] or '<none>' + note}")

    print("\nDone. This is a pre-audit loop — it makes a human audit cheaper, it does not replace one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
