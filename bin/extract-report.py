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
    """Return (span, parsed_obj, preceding_text) for each fenced JSON block that parses."""
    blocks = []
    for m in FENCE_RE.finditer(text):
        body = m.group(1).strip()
        if not body.startswith("{"):
            continue
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            continue
        blocks.append((m.span(), obj, text[max(0, m.start() - 200):m.start()]))
    return blocks


def select_appendix(blocks, nonce):
    """Pick the authoritative JSON block.

    With a per-run `nonce`, ONLY accept a block immediately preceded by the harness's
    `sak:nonce:<nonce>` marker. This defeats a malicious blueprint that gets the model to echo
    a fake JSON block — the attacker can't know the per-run nonce. Returns
    (selected_or_None, authenticated). When no nonce is required (static-only / legacy) the
    last block is returned and treated as authentic.
    """
    if nonce:
        marker = f"sak:nonce:{nonce}"
        authed = [b for b in blocks if marker in b[2]]
        return (authed[-1], True) if authed else (None, False)
    return (blocks[-1] if blocks else None), True


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
    if args.static_json:
        try:
            with open(args.static_json, encoding="utf-8") as fh:
                static_findings = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"warn: could not read static findings {args.static_json}: {exc}", file=sys.stderr)

    blocks = extract_json_blocks(raw)
    selected, authenticated = select_appendix(blocks, args.nonce)
    if args.nonce and blocks and not authenticated:
        # The model produced JSON block(s) but none carry this run's nonce marker — possible
        # injection (a malicious blueprint getting the model to echo a fake block). Fail safe:
        # never write report.json from an untrusted block.
        with open(args.out_md, "w", encoding="utf-8") as fh:
            fh.write("<!-- SECURITY: untrusted JSON appendix refused (no run nonce) -->\n" + raw)
        print("::error::SECURITY — the JSON appendix is not nonce-authenticated; refusing it. "
              "report.json NOT written; re-run the audit.", file=sys.stderr)
        return 3

    span = None
    if selected is not None:
        span, obj, _ = selected
        for f in obj.get("findings", []):
            f.setdefault("source", "llm")
        if static_findings:  # hybrid run — merge static into the LLM findings
            obj["findings"] = sak_lib.merge_findings(obj.get("findings", []), static_findings)
    elif static_findings:
        # No LLM block — assemble the report from the static findings alone (static-only tier).
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
