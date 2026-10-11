#!/usr/bin/env python3
"""Posture scanner CLI. Run as a module from the repo root (this package uses relative imports,
so it needs to run as part of the `scanner` package, not as a bare script):

    python3 -m scanner.cli scan   [--cohort PATH] [--out PATH] [--baseline PATH] [--network mainnet]
    python3 -m scanner.cli render REPORT.json [--out PAGE.md]
    python3 -m scanner.cli diff  OLD_REPORT.json NEW_REPORT.json [--json]

See scanner/README.md for a quickstart and docs/posture-scanner.md for the full design.
"""
import argparse
import glob
import os
import sys

from . import cohort as cohort_mod
from . import diff as diff_mod
from . import gateway
from . import report as report_mod
from . import site as site_mod

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_COHORT_PATH = os.path.join(ROOT, "scanner", "data", "cohort.json")
# The full-detail cohort: every entity this operator wants covered locally, including third
# parties and the notes that name them -- never committed (.gitignore excludes it), mirroring
# DEFAULT_FULL_RESULTS_DIR below. When this file is present, a default (no --cohort) `scan`
# reads it instead of the public cohort; when it's absent, `scan` falls back to
# DEFAULT_COHORT_PATH, so a plain clone of this repo still scans something. See cmd_scan.
DEFAULT_FULL_COHORT_PATH = os.path.join(ROOT, "scanner", "data", "cohort-full.json")
# The repo-relative form of the PUBLIC cohort path, recorded as `cohort_source` in a published
# report even when the full cohort was actually read -- a published report must never name a
# gitignored file's path, since that path itself is not something a stranger reading the repo
# could resolve or verify. See cmd_scan's use of this as `cohort_source_override`.
_PUBLIC_COHORT_SOURCE = os.path.relpath(DEFAULT_COHORT_PATH, ROOT)
DEFAULT_RESULTS_DIR = os.path.join(ROOT, "scanner", "results")
# Full-detail scan output: every entity, every check's real reason/evidence regardless of
# embargo status. Never committed (.gitignore excludes it) -- DEFAULT_RESULTS_DIR, above, is
# the PUBLIC directory and from here on only ever receives what
# site.redact_for_publication(result) leaves standing. This is also where a scan's own
# baseline lookup (see _default_baseline_path below) reads from, so Check 4's continuity is
# computed against full history, not the redacted copy a third party's withheld entity would
# otherwise silently lose from the picture.
DEFAULT_FULL_RESULTS_DIR = os.path.join(ROOT, "scanner", "results-full")


def _default_baseline_path(results_dir, before=None):
    """The most recent *.json in results_dir (by filename, which sort lexically in time order
    since scan_id/date-derived filenames are zero-padded), or None if the directory is empty.
    `before` excludes a specific path (the file this run is about to write) from consideration.
    """
    candidates = sorted(glob.glob(os.path.join(results_dir, "*.json")))
    if before is not None and before in candidates:
        candidates.remove(before)
    return candidates[-1] if candidates else None


def cmd_scan(args):
    # --cohort is exact: whatever the caller names, that's what's read and what cohort_source
    # records, no fallback and no source override. With no --cohort, a real operator run wants
    # the full local cohort when one exists (see DEFAULT_FULL_COHORT_PATH's docstring); a plain
    # clone of this repo, which never has that gitignored file, transparently gets the public
    # cohort instead. Either way, the report's own `cohort_source` field must name a path a
    # stranger reading the published report could actually resolve -- never the gitignored
    # file's own path -- so the override is set alongside the fallback, not derived from it
    # later.
    cohort_source_override = None
    if args.cohort:
        cohort_path = args.cohort
    elif os.path.exists(DEFAULT_FULL_COHORT_PATH):
        cohort_path = DEFAULT_FULL_COHORT_PATH
        cohort_source_override = _PUBLIC_COHORT_SOURCE
    else:
        cohort_path = DEFAULT_COHORT_PATH
    entities = cohort_mod.load_cohort(cohort_path)

    base_url = args.base_url or (
        gateway.GATEWAY_URL_STOKENET if args.network == "stokenet" else gateway.GATEWAY_URL_MAINNET
    )

    out_path = args.out
    baseline_path = args.baseline
    if baseline_path is None and not args.no_baseline:
        # The full-detail directory, not the public one: Check 4's baseline continuity needs
        # every cohort entity's real prior evidence, including third-party rows the public
        # report withholds entirely (see DEFAULT_FULL_RESULTS_DIR's docstring, above).
        baseline_path = _default_baseline_path(DEFAULT_FULL_RESULTS_DIR, before=out_path)

    previous_report = None
    if baseline_path:
        previous_report = report_mod.load_report(baseline_path)
        print(f"Using baseline: {baseline_path}", file=sys.stderr)
    else:
        print("No baseline found -- this scan establishes the baseline.", file=sys.stderr)

    result = report_mod.run_scan(
        cohort_path, entities, previous_report=previous_report, base_url=base_url, network=args.network,
        cohort_source=cohort_source_override,
    )

    date_stamp = result["generated_at"][:10]  # "2026-09-08T09:15:00Z" -> "2026-09-08"
    if out_path is None:
        out_path = os.path.join(DEFAULT_RESULTS_DIR, f"{date_stamp}.json")
    full_out_path = os.path.join(DEFAULT_FULL_RESULTS_DIR, f"{date_stamp}.json")

    # The public results directory (tracked in git, served raw from GitHub) receives only the
    # gated report -- see scanner/site.py's redact_for_publication. The full-detail report,
    # including anything still under embargo and every third-party entity's real findings,
    # goes to results-full/ instead, which .gitignore excludes; it never reaches the tree that
    # gets pushed.
    report_mod.write_report(full_out_path, result)
    report_mod.write_report(out_path, site_mod.redact_for_publication(result))
    print(f"Wrote {full_out_path} (full detail -- not tracked, see .gitignore)", file=sys.stderr)
    print(f"Wrote {out_path} (gated for publication)", file=sys.stderr)
    print(f"Pinned state_version: {result['gateway']['pinned_state_version']}", file=sys.stderr)
    print(f"Entities scanned: {len(result['entities'])}", file=sys.stderr)

    if previous_report:
        d = diff_mod.diff_reports(previous_report, result)
        print("--- Diff vs baseline ---", file=sys.stderr)
        print(diff_mod.summarize(d), file=sys.stderr)

    return 0


def cmd_render(args):
    report = report_mod.load_report(args.report)
    # Gated the same as build() -- `render` is a general "point me at any report.json" tool,
    # and results-full/<date>.json (Check 4's own baseline source, see DEFAULT_FULL_RESULTS_DIR
    # above) is exactly the kind of report a caller can point it at. render_markdown's own
    # models.is_public substitution only covers a held check's reason/evidence; without this,
    # every third-party entity's real rows -- addresses, packages, the lot -- would still print
    # in full, and a held check's embargo.reason would too (see models.redact_embargo).
    gated = site_mod.redact_for_publication(report)
    md = report_mod.render_markdown(gated)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"Wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(md)
    return 0


def cmd_diff(args):
    old = report_mod.load_report(args.old_report)
    new = report_mod.load_report(args.new_report)
    d = diff_mod.diff_reports(old, new)
    if args.json:
        import json
        print(json.dumps(d, indent=2))
    else:
        print(diff_mod.summarize(d))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="scanner", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run one posture scan over the configured cohort.")
    p_scan.add_argument("--cohort", help=f"Cohort JSON path (default: {DEFAULT_COHORT_PATH})")
    p_scan.add_argument("--out", help="Output report path (default: scanner/results/<date>.json)")
    p_scan.add_argument("--baseline", help="Prior report to diff Check 4 against (default: most recent file in scanner/results/)")
    p_scan.add_argument("--no-baseline", action="store_true", help="Force a baseline-establishing run even if prior results exist.")
    p_scan.add_argument("--network", choices=["mainnet", "stokenet"], default="mainnet")
    p_scan.add_argument("--base-url", help="Override the Gateway base URL (mainly for testing against Stokenet or a local Gateway).")
    p_scan.set_defaults(func=cmd_scan)

    p_render = sub.add_parser("render", help="Render a report.json to a human-readable Markdown page (no network read).")
    p_render.add_argument("report", help="Path to a report.json written by `scan`.")
    p_render.add_argument("--out", help="Write Markdown here (default: stdout).")
    p_render.set_defaults(func=cmd_render)

    p_diff = sub.add_parser("diff", help="Diff two previously-written report.json files.")
    p_diff.add_argument("old_report")
    p_diff.add_argument("new_report")
    p_diff.add_argument("--json", action="store_true", help="Print the full machine-readable diff instead of a summary.")
    p_diff.set_defaults(func=cmd_diff)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (cohort_mod.CohortError, gateway.GatewayError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
