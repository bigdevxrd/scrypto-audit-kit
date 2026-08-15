"""Shared helpers for scrypto-audit-kit — pure, stdlib-only, no MCP, no subprocess.

Both the CI gate (bin/ci-gate.py) and the MCP server (bin/mcp_server.py) build on
these so the same logic is used everywhere and is unit-tested in tests/test_sak_lib.py.

Everything operates on a report dict shaped by schema/audit-report.schema.json.
"""
import datetime
import glob
import hashlib
import json
import os

SEV_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# The two tiers a run can execute. `tiers` is a FACT about a run — which analyses actually ran —
# and is the only thing attest.py may derive an attestation mode from. Deliberately not the same
# vocabulary as the L1/L2/L3 trust ladder in VISION.md: that ladder is about who WITNESSED a run,
# which is a different axis (see docs/attestation-levels.md).
TIER_STATIC = "static"
TIER_LLM = "llm"


def _kit_root():
    """The kit checkout root, if we are running from one (bin/ sits one level below it)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def kit_version():
    """Kit version: the VERSION file of a real kit clone, else the installed metadata.

    The VERSION file is trusted only beside an `audit.sh` — installed, the sibling directory is
    site-packages, which we do not own, and this string is stamped into report provenance.
    """
    root = _kit_root()
    if os.path.isfile(os.path.join(root, "audit.sh")):
        try:
            with open(os.path.join(root, "VERSION"), encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            pass
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version("scrypto-audit-kit")
        except PackageNotFoundError:
            return "unknown"
    except ImportError:
        return "unknown"


def target_files(pkg_dir):
    """The files a run analyzes, in the exact order audit.sh feeds them to sha256.

    Mirrors audit.sh's TARGET_FILES: Cargo.toml, then every .rs under src/ sorted, then every
    .rs under tests/ sorted (only when tests/ exists). The ordering is load-bearing — it defines
    source_hash, which is the anchor an on-chain attestation binds to, so this function and the
    shell must never drift. tests/test_attest.py pins them against each other.
    """
    files = [os.path.join(pkg_dir, "Cargo.toml")]
    for sub in ("src", "tests"):
        base = os.path.join(pkg_dir, sub)
        if not os.path.isdir(base):
            continue
        found = []
        for root, _dirs, names in os.walk(base):
            found.extend(os.path.join(root, n) for n in names if n.endswith(".rs"))
        files.extend(sorted(found))
    return files


def source_hash(pkg_dir):
    """sha256 (hex) of the analyzed source, concatenated — the anchor an attestation binds to.

    Byte-identical to audit.sh's SOURCE_HASH, including its `cat ... 2>/dev/null` behaviour of
    silently skipping a file it cannot read. Returns "" when nothing was readable, so callers
    can fail closed on a missing anchor rather than attesting to nothing.
    """
    h = hashlib.sha256()
    read_any = False
    for path in target_files(pkg_dir):
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            read_any = True
        except OSError:
            continue  # `cat` skips unreadable files too
    return h.hexdigest() if read_any else ""


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


UNKNOWN_RANK = 99  # an unrecognised/blank severity outranks 'critical' so it can never slip under a gate


def _norm_severity(finding):
    return str(finding.get("severity", "")).strip().lower()


def _rank(finding):
    # fail-safe: unknown/blank severities rank above everything except an explicit `none` gate
    return SEV_RANK.get(_norm_severity(finding), UNKNOWN_RANK)


def _label_for_rank(rank):
    if rank == 0:
        return None
    if rank == UNKNOWN_RANK:
        return "unknown"
    return next((k for k, v in SEV_RANK.items() if v == rank), None)


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
    """Count findings by normalised severity label, e.g. {'critical': 2, 'high': 1}."""
    counts = {}
    for f in findings:
        sev = _norm_severity(f)
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def counts_summary(counts):
    """Render counts as 'critical:2, high:1' in severity order (unknown labels last), or 'none'."""
    known = [f"{s}:{counts[s]}" for s in SEV_ORDER if counts.get(s)]
    unknown = [f"{k or '<blank>'}:{counts[k]}" for k in counts if k not in SEV_RANK and counts[k]]
    return ", ".join(known + unknown) or "none"


def gate_verdict(report, fail_on="high"):
    """Decide whether a report passes a severity gate.

    fail_on: none | low | medium | high | critical. Returns a dict with passed,
    worst severity present, the threshold, per-severity counts, and total.
    """
    fo = (fail_on or "high").lower()
    if fo == "none":
        threshold = UNKNOWN_RANK + 1  # never fails on severity (not even an unknown label)
    elif fo in SEV_RANK:
        threshold = SEV_RANK[fo]
    else:
        raise ValueError(f"fail_on must be none|low|medium|high|critical, got {fail_on!r}")

    findings = report.get("findings", [])
    worst = max((_rank(f) for f in findings), default=0)
    worst_label = _label_for_rank(worst)
    return {
        "passed": worst < threshold,
        "fail_on": fo,
        "worst": worst_label,
        "counts": severity_counts(findings),
        "total": len(findings),
    }


class GateError(Exception):
    """A report could not be evaluated — callers MUST treat this as fail-closed (do not pass)."""


def collect_findings(path, allow_missing=False):
    """Gather findings from a report file (or a directory of them), failing CLOSED.

    Returns a flat list of findings. Raises GateError on a missing, unreadable, or malformed
    report so every caller — the CLI gate, the MCP gate, an agent's audit->attest loop — fails
    closed instead of passing an un-audited target. When allow_missing is set and no report
    exists at all, returns None so the caller can choose to pass explicitly.

    This is the single source of truth for "what does the gate see"; do not re-open reports
    with a bare .get("findings", []) (that silently fails OPEN on a missing/empty report).
    """
    files = find_reports(path)
    if not files:
        if allow_missing:
            return None
        raise GateError(f"no report.json at {path}")
    findings = []
    for fp in files:
        try:
            report = load_report(fp)
        except (OSError, ValueError) as exc:  # ValueError covers json.JSONDecodeError
            raise GateError(f"unreadable report {fp}: {exc}")
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise GateError(f"report {fp} has no findings array")
        findings.extend(report["findings"])
    return findings


def finding_signature(finding):
    """A stable-ish identity for a finding across runs.

    Keyed on (class, title, severity) — NOT the F-### id (assigned per-run) and NOT location
    (line numbers shift when code is edited). Severity is included so a low-severity finding can
    never collide with — and silently hide — a higher-severity one sharing a class/title.
    Heuristic; confirm with show_finding_source when it matters.
    """
    return "{}::{}::{}".format(
        str(finding.get("class", "")).strip().lower(),
        str(finding.get("title", "")).strip().lower(),
        _norm_severity(finding),
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
    # Confine the read to base_dir. A finding's `location` can originate from an untrusted
    # blueprint (the LLM tier echoes model-chosen paths) or a supplied report.json, so an
    # absolute path, a `../` escape, or a symlink pointing outside the package must NOT read
    # arbitrary host files. realpath() also collapses in-package symlinks that resolve outside.
    base_real = os.path.realpath(base_dir)
    resolved = os.path.realpath(os.path.join(base_real, file_part))
    if os.path.isabs(file_part) or os.path.commonpath([resolved, base_real]) != base_real:
        return {"error": "location escapes the package directory", "location": location}
    path = resolved
    if not os.path.isfile(path):
        return {"error": "file not found", "file": file_part}
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
    """The highest severity label present, None if empty, or 'unknown' for unrecognised labels."""
    return _label_for_rank(max((_rank(f) for f in findings), default=0))


def _finding_location(finding):
    return str(finding.get("location", "")).strip().lower()


def merge_findings(primary, extra):
    """Append `extra` findings to `primary`, deduping the same location-AWARE way on both sides.

    Against `primary` (the LLM pass): skip an extra that shares BOTH signature (class, title,
    severity) AND location with an OPEN primary finding — mirroring the extra-vs-extra keying
    below. This used to be location-INDEPENDENT (bare signature only), on the theory that the
    LLM and static pass often cite the same issue a line or two apart and we want one entry, not
    two. In practice that let one LLM finding at one line swallow every static finding sharing
    its signature ANYWHERE in the file — including genuinely distinct footguns at other lines,
    e.g. `raw arithmetic` at :86 silently eating the unrelated one at :98
    (BUG-HUNT-2026-07-18 M1). A pre-audit tool's worst failure mode is a false "all clear", so a
    same-line match is required to treat the two as one issue; different lines now both survive.

    A primary finding the model marked non-open (`status: false_positive`, `wontfix`, ...) does
    NOT suppress a same-location extra, either: the static rule is deterministic, reproducible
    ground truth, and a non-deterministic model opinion on that exact spot must not silently
    erase it from a `status=open` view (the M1 write-up's "status-blind" facet).

    Among the `extra` findings themselves (the static pass): dedup is location-AWARE. Two static
    findings that share a signature but sit at different locations — e.g. `raw arithmetic` at
    src/lib.rs:86 and :98 — are genuinely distinct footguns, so both survive; only a true duplicate
    (same signature AND same location) is dropped. Keying extra-vs-extra on the bare signature (the
    old behavior) silently collapsed them into one.

    Returns a new list: primary order preserved, then the genuinely-new extras."""
    primary_open_keys = {
        (finding_signature(f), _finding_location(f))
        for f in primary
        if str(f.get("status", "open")).lower() == "open"
    }
    seen_extra = set()
    merged = list(primary)
    for f in extra:
        key = (finding_signature(f), _finding_location(f))
        if key in primary_open_keys:
            continue
        if key in seen_extra:
            continue
        merged.append(f)
        seen_extra.add(key)
    return merged


def build_report(findings, pkg_dir=None):
    """Assemble a schema-shaped report dict from a findings list alone — the static-only tier.

    Pass `pkg_dir` (the package that was analyzed) to get a report that is complete and
    schema-VALID on its own, including the `target.source_hash` anchor an attestation needs.
    That is the pip-only path docs/sdk.md documents; without it there is no stamper in the
    installed package and the resulting payload cannot be attested.

    Omitting `pkg_dir` keeps the historical behaviour — empty kit/target for a caller that
    stamps its own provenance afterwards, which is what extract_report.py does on the clone
    path. It yields a deliberately INCOMPLETE report; attest.build_payload refuses it rather
    than attesting to a missing anchor.
    """
    by_class = {}
    for f in findings:
        by_class.setdefault(f.get("class", "?"), []).append(f.get("id", "?"))
    coverage = [{"class": c, "status": "findings", "findings": ids} for c, ids in sorted(by_class.items())]

    kit, target = {}, {}
    if pkg_dir is not None:
        pkg_dir = os.path.abspath(pkg_dir)
        kit = {
            "version": kit_version(),
            "model": "static-only",
            # The fact that drives the attestation mode. Only the static tier ran here, by
            # construction — this function is what "no LLM pass" means.
            "tiers": [TIER_STATIC],
            "checklist_version": "n/a",  # no checklist walk happens in the static-only tier
            "generated_at": datetime.datetime.now(datetime.timezone.utc)
                                    .strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        target = {
            "repo": os.path.basename(os.path.dirname(pkg_dir)),
            "package": os.path.basename(pkg_dir),
            "source_hash": source_hash(pkg_dir),
            "files_analyzed": len([p for p in target_files(pkg_dir) if os.path.isfile(p)]),
        }
    return {
        "schema_version": "1.0",
        "kit": kit,
        "target": target,
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
