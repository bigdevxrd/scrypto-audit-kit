"""Shared helpers for scrypto-audit-kit — pure, stdlib-only, no MCP, no subprocess.

Both the CI gate (bin/ci-gate.py) and the MCP server (bin/mcp_server.py) build on
these so the same logic is used everywhere and is unit-tested in tests/test_sak_lib.py.

Everything operates on a report dict shaped by schema/audit-report.schema.json.
"""
import glob
import json
import os

SEV_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def load_report(path):
    """Load a report.json into a dict."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def find_reports(path):
    """Resolve a path to a list of report json files (a file, or every *.json in a dir)."""
    if os.path.isdir(path):
        return sorted(glob.glob(os.path.join(path, "*.json")))
    return [path] if os.path.exists(path) else []


def newest_report(directory):
    """Return the most recently modified *.json in a directory, or None."""
    reports = find_reports(directory)
    if not reports:
        return None
    return max(reports, key=os.path.getmtime)


def _rank(finding):
    return SEV_RANK.get(str(finding.get("severity", "")).lower(), 0)


def filter_findings(report, severity_min=None, status=None):
    """Return findings at/above severity_min and (optionally) matching a status."""
    min_rank = SEV_RANK.get((severity_min or "").lower(), 0)
    out = []
    for f in report.get("findings", []):
        if _rank(f) < min_rank:
            continue
        if status and str(f.get("status", "open")).lower() != status.lower():
            continue
        out.append(f)
    return out


def severity_counts(findings):
    """Count findings by severity label, e.g. {'critical': 2, 'high': 1}."""
    counts = {}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def counts_summary(counts):
    """Render counts as 'critical:2, high:1' in severity order, or 'none'."""
    return ", ".join(f"{s}:{counts[s]}" for s in SEV_ORDER if counts.get(s)) or "none"


def gate_verdict(report, fail_on="high"):
    """Decide whether a report passes a severity gate.

    fail_on: none | low | medium | high | critical. Returns a dict with passed,
    worst severity present, the threshold, per-severity counts, and total.
    """
    fo = (fail_on or "high").lower()
    if fo == "none":
        threshold = 99  # never fails
    elif fo in SEV_RANK:
        threshold = SEV_RANK[fo]
    else:
        raise ValueError(f"fail_on must be none|low|medium|high|critical, got {fail_on!r}")

    findings = report.get("findings", [])
    worst = max((_rank(f) for f in findings), default=0)
    worst_label = next((k for k, v in SEV_RANK.items() if v == worst), None) if worst else None
    return {
        "passed": worst < threshold,
        "fail_on": fo,
        "worst": worst_label,
        "counts": severity_counts(findings),
        "total": len(findings),
    }


def finding_signature(finding):
    """A stable-ish identity for a finding across runs.

    Keyed on (class, title), NOT the F-### id (ids are assigned per-run by severity
    order) and NOT location (line numbers shift when code is edited). Heuristic —
    callers should confirm with show_finding_source when it matters.
    """
    return "{}::{}".format(
        str(finding.get("class", "")).strip().lower(),
        str(finding.get("title", "")).strip().lower(),
    )


def diff_reports(baseline, current):
    """Compare two reports by finding signature.

    Returns {fixed, still_open, new}: findings present only in baseline (fixed),
    in both (still_open), and only in current (new).
    """
    base = {finding_signature(f): f for f in baseline.get("findings", [])}
    cur = {finding_signature(f): f for f in current.get("findings", [])}
    return {
        "fixed": [base[s] for s in base if s not in cur],
        "still_open": [cur[s] for s in cur if s in base],
        "new": [cur[s] for s in cur if s not in base],
    }


def read_source_span(base_dir, location, context=3):
    """Read the source around a finding's `location` ('path/file.rs:line').

    Returns {file, line, snippet} with the cited line marked, or {error, ...}.
    Lets an agent (or human) verify a citation before acting on it.
    """
    if ":" not in location:
        return {"error": "location has no line number", "location": location}
    file_part, line_part = location.rsplit(":", 1)
    try:
        line = int(line_part.split("-")[0])
    except ValueError:
        return {"error": "unparseable line number", "location": location}
    path = os.path.join(base_dir, file_part)
    if not os.path.isfile(path):
        return {"error": "file not found", "path": path}
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    start = max(1, line - context)
    end = min(len(lines), line + context)
    snippet = "".join(
        "{:>5}{} {}".format(i, ">" if i == line else " ", lines[i - 1])
        for i in range(start, end + 1)
    )
    return {"file": file_part, "line": line, "snippet": snippet}


def worst_severity(findings):
    """The highest severity label present in a findings list, or None."""
    worst = max((_rank(f) for f in findings), default=0)
    return next((k for k, v in SEV_RANK.items() if v == worst), None) if worst else None


def merge_findings(primary, extra):
    """Append `extra` findings to `primary`, skipping any whose (class, title) signature is
    already present (so the static pass doesn't duplicate what the LLM already flagged).
    Returns a new list: primary order preserved, then the genuinely-new extras."""
    seen = {finding_signature(f) for f in primary}
    merged = list(primary)
    for f in extra:
        sig = finding_signature(f)
        if sig not in seen:
            merged.append(f)
            seen.add(sig)
    return merged


def build_report(findings):
    """Assemble a minimal schema-shaped report dict from a findings list alone — used when
    there is no LLM pass (the static-only tier). Provenance (kit/target) is stamped separately."""
    by_class = {}
    for f in findings:
        by_class.setdefault(f.get("class", "?"), []).append(f.get("id", "?"))
    coverage = [{"class": c, "status": "findings", "findings": ids} for c, ids in sorted(by_class.items())]
    return {
        "schema_version": "1.0",
        "kit": {},
        "target": {},
        "summary": {
            "overall_risk": worst_severity(findings) or "info",
            "one_liner": f"Static-only pre-audit: {len(findings)} deterministic finding(s). "
                         "Run the full pre-audit (with an API key) for semantic findings and full checklist coverage.",
        },
        "findings": findings,
        "checklist_coverage": coverage,
        "open_questions": [
            "Static-only tier — deterministic rules only, not the full LLM checklist walk. "
            "Run `./audit.sh` for semantic coverage.",
        ],
    }


def render_findings_md(findings, heading):
    """Render a findings list as a markdown section (used for the static report + merge section)."""
    out = [f"## {heading}", ""]
    if not findings:
        return "\n".join(out + ["_None._", ""])
    for f in findings:
        rule = f"  ·  rule `{f['rule']}`" if f.get("rule") else ""
        out.append(f"### {f.get('id', '?')} — {f.get('title', '')}")
        out.append("")
        out.append(f"**{f.get('severity', '?')}** · {f.get('class', '?')} · `{f.get('location', '?')}`{rule}")
        out.append("")
        for label, key in (("What", "what"), ("Why it matters", "why"), ("Suggested direction", "suggested_direction")):
            if f.get(key):
                out.append(f"- **{label}:** {f[key]}")
        out.append("")
    return "\n".join(out)
