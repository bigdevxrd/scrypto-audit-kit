#!/usr/bin/env python3
"""Turn a pre-audit report.json into an on-chain attestation payload + a Radix manifest.

The bridge from a kit run to the L3 attestation registry (see attestation/). It reads the
report's source_hash, hashes the report (and optionally the built wasm), counts findings by
severity, derives the level, and renders a transaction manifest that calls `attest(...)` on a
deployed registry component. Stdlib only. Importable + CLI; also the attestation_payload MCP tool.
"""
import argparse
import hashlib
import json
import sys

import sak_lib


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _derive_level(report):
    """L1-static if there's no LLM pass, else L2-hybrid."""
    if "static-only" in str(report.get("kit", {}).get("model", "")).lower():
        return "L1-static"
    if any(str(f.get("source", "")).lower() == "llm" for f in report.get("findings", [])):
        return "L2-hybrid"
    return "L1-static"


def build_payload(report_path, wasm_path="", level=""):
    """Compute the AttestationInput payload (the fields the registry's attest() expects)."""
    report = sak_lib.load_report(report_path)
    counts = sak_lib.severity_counts(report.get("findings", []))
    kit = report.get("kit", {})
    return {
        "source_hash": report.get("target", {}).get("source_hash", ""),
        "report_hash": _sha256_file(report_path),
        "wasm_hash": _sha256_file(wasm_path) if wasm_path else "",
        "kit_version": kit.get("version", "unknown"),
        "checklist_version": kit.get("checklist_version", "unknown"),
        "level": level or _derive_level(report),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
    }


_STR_FIELDS = ["source_hash", "report_hash", "wasm_hash", "kit_version", "checklist_version", "level"]
_U16_FIELDS = ["critical", "high", "medium", "low", "info"]


def render_manifest(payload, component, account, fee="10"):
    """Render a Radix transaction manifest calling attest(AttestationInput) + depositing the NFT."""
    def quote(v):
        return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'

    rows = [f"        {quote(payload[k])}," for k in _STR_FIELDS]
    rows += [f"        {int(payload[k])}u16," for k in _U16_FIELDS]
    rows[-1] = rows[-1].rstrip(",")  # the final tuple element takes no trailing comma
    tuple_body = "\n".join(rows)
    return f"""# scrypto-audit-kit attestation — generated; review before submitting.
# The account deposit method may need adjusting to your network's current API.
CALL_METHOD
    Address("{account}")
    "lock_fee"
    Decimal("{fee}")
;
CALL_METHOD
    Address("{component}")
    "attest"
    Tuple(
{tuple_body}
    )
;
CALL_METHOD
    Address("{account}")
    "try_deposit_batch_or_abort"
    Expression("ENTIRE_WORKTOP")
    Enum<0u8>()
;
"""


def main():
    ap = argparse.ArgumentParser(description="Attestation payload + manifest from a report.json.")
    ap.add_argument("report", help="path to a report.json")
    ap.add_argument("--wasm", default="", help="path to the built blueprint wasm to hash")
    ap.add_argument("--level", default="", help="override the derived level (L1-static / L2-hybrid / ...)")
    ap.add_argument("--component", default="", help="deployed attestation registry component address")
    ap.add_argument("--account", default="", help="your account address (pays the fee, receives the NFT)")
    ap.add_argument("--out-manifest", default="", help="write the manifest to this file")
    ap.add_argument("--json", action="store_true", help="print the payload JSON (even if --component is given)")
    args = ap.parse_args()

    payload = build_payload(args.report, args.wasm, args.level)
    sys.stderr.write(f"[attest] level {payload['level']} · {payload['critical']}C/{payload['high']}H · "
                     f"source {payload['source_hash'][:12]}\n")

    if args.component and args.account and not args.json:
        manifest = render_manifest(payload, args.component, args.account)
        if args.out_manifest:
            with open(args.out_manifest, "w", encoding="utf-8") as fh:
                fh.write(manifest)
        else:
            sys.stdout.write(manifest)
    else:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
