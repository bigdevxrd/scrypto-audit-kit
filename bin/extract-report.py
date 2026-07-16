#!/usr/bin/env python3
"""Split a pre-audit run into a clean markdown report + a machine-readable report.json.

The model emits a human markdown report followed by a fenced ```json block conforming
to schema/audit-report.schema.json. This script:

  1. pulls the LAST valid JSON block out of the raw output,
  2. stamps it with authoritative provenance (kit version, model, checklist version,
     source hash, ...) — the harness knows these, the model does not,
  3. writes report.json,
  4. rewrites the markdown without the JSON appendix, with a one-line provenance header.

Soft-fails: if no valid JSON block is found, the markdown is still written and the script
exits 0 (the human report is never lost to a structured-output hiccup). Schema validation
is performed only if `jsonschema` is importable — it is never a hard dependency.

Stdlib only.
"""
import argparse
import json
import re
import sys

import sak_lib

FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)


def extract_json_blocks(text):
    """Return (span, parsed_obj) for each fenced JSON block that parses, in document order."""
    blocks = []
    for m in FENCE_RE.finditer(text):
        body = m.group(1).strip()
        if not body.startswith("{"):
            continue
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            continue
        blocks.append((m.span(), obj))
    return blocks


def select_appendix(text, blocks, nonce):
    """Pick the authoritative JSON block.

    With a per-run `nonce`, a block is authentic ONLY if the `sak:nonce:<nonce>` marker is the
    LAST non-whitespace content immediately before its opening fence — ADJACENCY, not a fuzzy
    "within 200 chars" window. The old window let a small real block lend its marker to a LATER
    attacker block (which then won as the last authed block); adjacency + scanning only the gap
    since the previous block closes that. If MORE THAN ONE block authenticates, refuse (a run
    carries exactly one) and prefer the FIRST otherwise. Without a nonce (static-only / legacy)
    the last block is returned.

    Returns (selected_block_or_None, authenticated, ambiguous).
    """
    if not nonce:
        return (blocks[-1] if blocks else None), True, False
    marker = f"sak:nonce:{nonce}"
    authed = []
    prev_end = 0
    for span, obj in blocks:
        start, end = span
        preamble = text[prev_end:start]  # only the gap since the previous block — no reach-back
        prev_end = end
        idx = preamble.rfind(marker)
        if idx == -1:
            continue
        tail = preamble[idx + len(marker):].replace("-->", "", 1)  # only the comment close may follow
        if tail.strip() == "":
            authed.append((span, obj))
    if len(authed) > 1:
        return None, False, True  # ambiguous — refuse, fail safe
    return (authed[0] if authed else None), bool(authed), False


def strip_json_appendix(text, span):
    """Remove the JSON fenced block, plus the `<!-- machine-readable -->` marker and the
    `---` rule that precede it, from the markdown."""
    start, end = span
    before = text[:start]
    after = text[end:]
    # the marker comment sits just above the block; the `---` rule sits just above that
    before = re.sub(r"\s*<!--[^>]*?(?:machine-readable|sak:nonce:)[^>]*?-->\s*$", "\n", before, flags=re.IGNORECASE)
    before = re.sub(r"\s*\n-{3,}[ \t]*$", "\n", before)
    cleaned = before.rstrip() + "\n"
    if after.strip():
        cleaned += after.lstrip()
    return cleaned


def soft_validate(obj, schema_path):
    """Best-effort schema validation. Returns a list of human-readable problems (empty = ok/skipped)."""
    try:
        import jsonschema  # type: ignore
    except Exception:
        return []  # not installed — skip silently
    try:
        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
        jsonschema.Draft202012Validator(schema).validate(obj)
        return []
    except FileNotFoundError:
        return []
    except jsonschema.ValidationError as exc:  # type: ignore
        return [exc.message]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw", required=True, help="path to the raw markdown report (read)")
    ap.add_argument("--out-json", required=True, help="path to write report.json")
    ap.add_argument("--out-md", required=True, help="path to write the cleaned markdown (may equal --raw)")
    ap.add_argument("--kit-version", default="unknown")
    ap.add_argument("--model", default="unknown")
    ap.add_argument("--checklist-version", default="unknown")
    ap.add_argument("--reference-set", default="")
    ap.add_argument("--repo", default="")
    ap.add_argument("--package", default="")
    ap.add_argument("--source-hash", default="")
    ap.add_argument("--files", type=int, default=0)
    ap.add_argument("--generated-at", default="")
    ap.add_argument("--schema", default="", help="optional schema path for soft validation")
    ap.add_argument("--static-json", default="", help="optional JSON file of static findings to merge in")
    ap.add_argument("--nonce", default="", help="per-run nonce; only a JSON block carrying its marker is trusted")
    args = ap.parse_args()

    with open(args.raw, encoding="utf-8") as fh:
        raw = fh.read()

    static_findings = []
    static_ran = False
    if args.static_json:
        try:
            with open(args.static_json, encoding="utf-8") as fh:
                static_findings = json.load(fh)
            static_ran = True  # the static pass ran (even if it found nothing) — a clean run is attestable
        except (OSError, ValueError) as exc:
            print(f"warn: could not read static findings {args.static_json}: {exc}", file=sys.stderr)

    blocks = extract_json_blocks(raw)
    selected, authenticated, ambiguous = select_appendix(raw, blocks, args.nonce)
    if args.nonce and blocks and not authenticated:
        # JSON block(s) present but none is uniquely nonce-authenticated (missing marker, or
        # ambiguous — >1 authed). Possible injection: a blueprint getting the model to echo a
        # forged block. Fail safe — never write report.json, and WITHHOLD the model's prose
        # (a clean-looking narrative an operator might share) rather than emit it invisibly.
        reason = "ambiguous nonce (more than one authenticated block)" if ambiguous else "no run nonce"
        with open(args.out_md, "w", encoding="utf-8") as fh:
            fh.write("# ⚠ Pre-audit REFUSED — possible prompt injection\n\n"
                     f"The model's JSON appendix was not authenticated by this run's nonce ({reason}). "
                     "A blueprint may have injected a forged 'all clear' block, so report.json was NOT "
                     "written and the model's prose is withheld. Re-run the audit.\n")
        print(f"::error::SECURITY — the JSON appendix is not nonce-authenticated ({reason}); refusing it. "
              "report.json NOT written; re-run the audit.", file=sys.stderr)
        return 3

    span = None
    if selected is not None:
        span, obj = selected
        for f in obj.get("findings", []):
            f.setdefault("source", "llm")
        if static_findings:  # hybrid run — merge static into the LLM findings
            obj["findings"] = sak_lib.merge_findings(obj.get("findings", []), static_findings)
    elif static_ran:
        # No LLM block — assemble the report from the static pass alone (static-only tier). Build
        # it even when the pass found NOTHING: a clean audit is a first-class, attestable result
        # and the file-mode gate / L3 attestation both need a report.json to exist.
        obj = sak_lib.build_report(static_findings)
    else:
        # Neither — keep the human report, skip JSON. Never fail the pipeline.
        with open(args.out_md, "w", encoding="utf-8") as fh:
            fh.write(raw if raw.endswith("\n") else raw + "\n")
        print("warn: no machine-readable JSON block found — wrote markdown only", file=sys.stderr)
        return 0

    # Stamp authoritative provenance — overrides whatever the model put there.
    obj["schema_version"] = "1.0"
    kit = obj.setdefault("kit", {})
    kit.update({
        "version": args.kit_version,
        "model": args.model,
        "checklist_version": args.checklist_version,
        "generated_at": args.generated_at,
    })
    if args.reference_set:
        kit["reference_set"] = args.reference_set
    target = obj.setdefault("target", {})
    if args.repo:
        target["repo"] = args.repo
    if args.package:
        target["package"] = args.package
    if args.source_hash:
        target["source_hash"] = args.source_hash
    if args.files:
        target["files_analyzed"] = args.files

    problems = soft_validate(obj, args.schema) if args.schema else []
    for p in problems:
        print(f"warn: schema: {p}", file=sys.stderr)

    with open(args.out_json, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    # Cleaned markdown: the human body (minus the JSON appendix) + a static-findings section.
    cleaned = strip_json_appendix(raw, span) if span is not None else (raw.rstrip() + "\n")
    if static_findings:
        cleaned = cleaned.rstrip() + "\n\n" + sak_lib.render_findings_md(
            static_findings, "Static analysis (deterministic)")
    header = (
        f"<!-- scrypto-audit-kit {args.kit_version} · model {args.model} · "
        f"checklist {args.checklist_version} · source {args.source_hash[:12]} · {args.generated_at} -->\n"
    )
    with open(args.out_md, "w", encoding="utf-8") as fh:
        fh.write(header + cleaned)

    findings = obj.get("findings", [])
    by_sev = {}
    for f in findings:
        by_sev[f.get("severity", "?")] = by_sev.get(f.get("severity", "?"), 0) + 1
    sev_str = ", ".join(f"{k}:{v}" for k, v in sorted(by_sev.items())) or "none"
    extra = f"; {len(static_findings)} from static" if static_findings else ""
    print(f"report.json: {len(findings)} findings ({sev_str}){extra}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
