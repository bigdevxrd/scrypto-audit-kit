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

import attest
import gen_tests
import sak_lib
import static_analysis

def _kit_home():
    """Locate the kit's repo resources (audit.sh, prompts/, schema/).

    Order: $SAK_HOME, then walk up from this file looking for audit.sh (the bare-clone
    case — bin/ sits one level below the kit root), then the repo-layout default. This lets
    a pip-installed server find a kit clone via SAK_HOME while keeping clone behaviour
    byte-identical to the previous dirname(dirname(__file__)).
    """
    env = os.environ.get("SAK_HOME")
    if env and os.path.isfile(os.path.join(env, "audit.sh")):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    walk = here
    for _ in range(4):
        if os.path.isfile(os.path.join(walk, "audit.sh")):
            return walk
        parent = os.path.dirname(walk)
        if parent == walk:
            break
        walk = parent
    return os.path.dirname(here)  # default: bin/ -> kit root


KIT_DIR = _kit_home()
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
    # Only trust a report THIS run produced. A newest_report() fallback would return a stale,
    # unrelated package's report on any failure (bad path, compile fail, API error, injection
    # refusal) — letting an agent attest an un-audited package as clean. Require a clean exit
    # AND an emitted `json:` path; otherwise the caller gets an explicit error.
    if proc.returncode != 0:
        return None, log
    match = _JSON_PATH_RE.search(proc.stdout)
    report_path = match.group(1).strip() if match else None
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
        {passed, worst, fail_on, counts, total}. Fails CLOSED (passed=False, with an
        `error`) on a missing, empty, unreadable, or malformed report — an agent driving an
        audit->attest loop must never read a green light out of the absence of a report.
    """
    try:
        findings = sak_lib.collect_findings(report_path)
    except sak_lib.GateError as exc:
        return {"passed": False, "error": str(exc), "fail_on": fail_on,
                "worst": None, "counts": {}, "total": 0}
    return sak_lib.gate_verdict({"findings": findings}, fail_on)


def get_checklist() -> str:
    """Return the kit's Scrypto vulnerability checklist (the 11 classes + questions)."""
    if not os.path.isfile(CHECKLIST):
        raise RuntimeError(
            f"checklist not found at {CHECKLIST} — run the server from a scrypto-audit-kit "
            "clone, or set SAK_HOME to point at one")
    with open(CHECKLIST, encoding="utf-8") as fh:
        return fh.read()


def static_scan(package_path: str) -> dict:
    """Run only the deterministic static analysis — free, no API key, no model call.

    A fast, reproducible first pass that catches mechanical Scrypto footguns (unbounded
    drains, no-owner globalize, self-rotating roles, floats, hardcoded addresses, ...).
    Use it to triage cheaply before audit_package, or on its own.

    Args:
        package_path: Path to the Scrypto package (a dir with a src/ folder).

    Returns:
        {count, counts, findings} from the static rules (each finding has source="static").
    """
    findings = static_analysis.analyze_package(package_path)
    return {"count": len(findings), "counts": sak_lib.severity_counts(findings), "findings": findings}


def propose_tests(package_path: str) -> dict:
    """Generate scrypto-test property-test scaffolds for a package — free, no API.

    Reads the blueprint's roles and methods and proposes `#[ignore]`d test scaffolds (auth
    negative-paths, happy paths, a value-conservation invariant) to close coverage gaps. The
    scaffolds compile and stay ignored until implemented. The kit never writes them into the
    package — you (or the agent, with the user) save and fill them in.

    Args:
        package_path: Path to the Scrypto package (a dir with a src/ folder).

    Returns:
        {blueprint, count, specs, rust} — specs is structured; rust is the ready-to-save file.
    """
    return gen_tests.propose_tests(package_path)


def attestation_payload(report_path: str, component: str = "", account: str = "",
                        wasm_path: str = "", level: str = "") -> dict:
    """Build the on-chain attestation payload (and manifest) from a report — free, no API.

    Bridges a pre-audit report to the L3 attestation registry: computes the source/report/wasm
    hashes, severity counts, and level, and (when a component + account are given) renders a Radix
    transaction manifest that calls attest(). See the attestation/ blueprint.

    Args:
        report_path: Path to a report.json.
        component: Deployed attestation registry component address (for the manifest).
        account: Your account address (for the manifest).
        wasm_path: Optional path to the built blueprint wasm to hash.
        level: Optional override for the derived level.

    Returns:
        {payload, manifest?} — manifest is included when both component and account are given.
    """
    payload = attest.build_payload(report_path, wasm_path, level)
    result = {"payload": payload}
    if component and account:
        result["manifest"] = attest.render_manifest(payload, component, account)
    return result


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


TOOLS = (audit_package, static_scan, propose_tests, attestation_payload, get_findings,
         reaudit_diff, gate, get_checklist, show_finding_source)


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
