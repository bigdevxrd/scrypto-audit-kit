#!/usr/bin/env python3
"""MCP server for scrypto-audit-kit — the pre-audit as tools any agent can call.

Tools: audit_package, get_findings, reaudit_diff, gate, get_checklist, show_finding_source.
Together they enable the audit -> fix -> re-verify loop: the auditor stays read-only, the
agent (with a human in the loop) applies fixes, and reaudit_diff confirms what actually closed.

Run:   python3 bin/mcp_server.py            # stdio transport
Needs: pip install "mcp[cli]"               # or: pip install fastmcp
       ANTHROPIC_API_KEY in the environment (for audit_package / reaudit_diff)

The tool functions are plain and import-safe (no MCP import at module load), so they are
unit-tested in tests/ without the SDK installed.
"""
import os
import re
import subprocess
import sys

import sak_lib

KIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_SH = os.path.join(KIT_DIR, "audit.sh")
REPORTS_DIR = os.path.join(KIT_DIR, "audit-reports")
CHECKLIST = os.path.join(KIT_DIR, "prompts", "checklist.md")

_JSON_PATH_RE = re.compile(r"^\s*json:\s*(.+\.json)\s*$", re.MULTILINE)


def _run_audit(package_path, model, no_compile_check):
    """Run audit.sh and return (report_path_or_None, combined_log)."""
    if not os.path.isfile(AUDIT_SH):
        return None, f"audit.sh not found at {AUDIT_SH}"
    cmd = ["bash", AUDIT_SH, "--model", model]
    if no_compile_check:
        cmd.append("--no-compile-check")
    cmd.append(package_path)
    proc = subprocess.run(cmd, cwd=KIT_DIR, capture_output=True, text=True, check=False)
    log = proc.stdout + proc.stderr
    # Prefer the path audit.sh prints; fall back to the newest report json.
    match = _JSON_PATH_RE.search(proc.stdout)
    report_path = match.group(1).strip() if match else sak_lib.newest_report(REPORTS_DIR)
    return report_path, log


def audit_package(package_path: str, model: str = "claude", no_compile_check: bool = False) -> dict:
    """Run the pre-audit over a Scrypto package and return structured findings.

    Args:
        package_path: Path to the package (a dir with Cargo.toml + src/lib.rs).
        model: Analysis model — "claude" (default), "deepseek", or "both".
        no_compile_check: Skip the cargo wasm pre-flight (use if the toolchain isn't set up).

    Returns:
        The report.json contents (summary, findings, checklist_coverage, ...) with an added
        report_path, or {"error", "log"} if the run produced no report.
    """
    report_path, log = _run_audit(package_path, model, no_compile_check)
    if not report_path or not os.path.isfile(report_path):
        return {"error": "audit produced no report.json", "log": log[-4000:]}
    report = sak_lib.load_report(report_path)
    report["report_path"] = report_path
    return report


def get_findings(report_path: str, severity_min: str = "", status: str = "") -> dict:
    """Read findings from an existing report.json, optionally filtered.

    Args:
        report_path: Path to a report.json.
        severity_min: Only findings at/above this severity (info|low|medium|high|critical).
        status: Only findings with this status (open|fixed|wontfix|false_positive).

    Returns:
        {count, counts, findings} for the matching findings.
    """
    report = sak_lib.load_report(report_path)
    findings = sak_lib.filter_findings(report, severity_min or None, status or None)
    return {"count": len(findings), "counts": sak_lib.severity_counts(findings), "findings": findings}


def reaudit_diff(package_path: str, baseline_report_path: str, model: str = "claude",
                 no_compile_check: bool = False) -> dict:
    """Re-audit a package and diff against a baseline report — the verify step of the loop.

    Args:
        package_path: The package to re-audit (after applying fixes).
        baseline_report_path: An earlier report.json to compare against.
        model: Analysis model — "claude" (default), "deepseek", or "both".
        no_compile_check: Skip the cargo wasm pre-flight.

    Returns:
        {fixed, still_open, new} findings (matched by class+title) + summary counts + report_path.
    """
    baseline = sak_lib.load_report(baseline_report_path)
    report_path, log = _run_audit(package_path, model, no_compile_check)
    if not report_path or not os.path.isfile(report_path):
        return {"error": "re-audit produced no report.json", "log": log[-4000:]}
    diff = sak_lib.diff_reports(baseline, sak_lib.load_report(report_path))
    diff["summary"] = {k: len(v) for k, v in diff.items() if isinstance(v, list)}
    diff["report_path"] = report_path
    return diff


def gate(report_path: str, fail_on: str = "high") -> dict:
    """Apply the severity gate to a report — does it pass at this threshold?

    Args:
        report_path: Path to a report.json (or a directory of them).
        fail_on: Highest severity allowed before failing (none|low|medium|high|critical).

    Returns:
        {passed, worst, fail_on, counts, total}.
    """
    findings = []
    for fp in sak_lib.find_reports(report_path):
        findings.extend(sak_lib.load_report(fp).get("findings", []))
    return sak_lib.gate_verdict({"findings": findings}, fail_on)


def get_checklist() -> str:
    """Return the kit's Scrypto vulnerability checklist (the 11 classes + questions)."""
    with open(CHECKLIST, encoding="utf-8") as fh:
        return fh.read()


def show_finding_source(report_path: str, finding_id: str, package_path: str = "",
                        context: int = 3) -> dict:
    """Show the source a finding cites, so you can verify the citation before acting on it.

    Args:
        report_path: Path to a report.json.
        finding_id: The finding id, e.g. "F-001".
        package_path: The audited package dir (locations are relative to it; defaults to cwd).
        context: Lines of context above/below the cited line.

    Returns:
        {finding, source} where source is the cited code with the line marked, or {error}.
    """
    report = sak_lib.load_report(report_path)
    finding = next((f for f in report.get("findings", []) if f.get("id") == finding_id), None)
    if finding is None:
        return {"error": f"no finding {finding_id} in {report_path}"}
    base = package_path or os.getcwd()
    return {"finding": finding, "source": sak_lib.read_source_span(base, finding.get("location", ""), context)}


TOOLS = (audit_package, get_findings, reaudit_diff, gate, get_checklist, show_finding_source)


def _import_fastmcp():
    """Import FastMCP from the official SDK, falling back to the standalone package."""
    try:
        from mcp.server.fastmcp import FastMCP  # pip install "mcp[cli]"
        return FastMCP
    except ImportError:
        from fastmcp import FastMCP  # pip install fastmcp
        return FastMCP


def build_server():
    """Construct the FastMCP server with all tools registered."""
    fast_mcp = _import_fastmcp()
    server = fast_mcp("scrypto-audit-kit")
    for fn in TOOLS:
        server.tool()(fn)
    return server


def main():
    try:
        server = build_server()
    except ImportError:
        sys.stderr.write(
            'scrypto-audit-kit MCP server needs the MCP SDK:\n'
            '  pip install "mcp[cli]"   (or: pip install fastmcp)\n'
        )
        return 1
    server.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
