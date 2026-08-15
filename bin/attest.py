#!/usr/bin/env python3
"""Turn a pre-audit report.json into an on-chain attestation payload + a Radix manifest.

The bridge from a kit run to the attestation registry (see attestation/). It reads the report's
source_hash, hashes the report (and optionally the built wasm), counts findings by severity,
records which tiers ran, and renders a transaction manifest that calls `attest(...)` on a
deployed registry component. Stdlib only. Importable + CLI; also the attestation_payload MCP tool.

It records FACTS, not a trust level. The payload carries `mode` (static | hybrid) — what
analysis actually ran — and never an L-number. The L1/L2/L3 ladder is about who witnessed a run,
which no self-attestation can establish about itself; a reader computes the rung from mode +
attester identity + issuer_verified, per docs/attestation-levels.md. This is the same split SLSA
makes: the producer asserts facts, the consumer derives the level.
"""
import argparse
import hashlib
import json
import sys

try:  # installed: real submodules of the scrypto_audit_kit package
    from . import sak_lib
except ImportError:  # bare clone / direct script run: bin/ is itself on sys.path
    import sak_lib


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _u16(n):
    """Clamp a count to the u16 the on-chain field accepts (so >65535 findings can't break it)."""
    try:
        return max(0, min(int(n), 65535))
    except (TypeError, ValueError):
        return 0


# The three non-empty tier combinations, named. A closed set, so the on-chain enum check makes
# anything else unrepresentable. Three values rather than two on purpose: with only
# static|hybrid, a `--no-static` run (LLM tier only) would have to be called "hybrid", which
# asserts a deterministic pass that never ran — the same over-claim in a new place.
MODE_STATIC = "static"   # deterministic ruleset only
MODE_LLM = "llm"         # LLM checklist pass only (--no-static)
MODE_HYBRID = "hybrid"   # both tiers ran


class AttestationError(Exception):
    """The report cannot be attested. Fail closed — never emit a payload that overclaims."""


def _derive_mode(report):
    """Which tiers actually ran, as a fact read from `kit.tiers`.

    This is NOT a trust level. It says what analysis was executed, nothing about who witnessed
    it — the L1/L2/L3 ladder is computed by the READER from this plus attester identity, per
    docs/attestation-levels.md.

    Every tier must be positively present to be claimed. The previous implementation parsed
    `kit.model` for the substring "static-only" and returned the HIGHER claim on anything else —
    so an absent, unknown, or user-supplied model string asserted that the LLM checklist pass had
    run when it had not, and `--no-static` (no deterministic tier at all) still derived "hybrid".

    A report with no `tiers` at all predates 0.8.0. It derives `static`: the lowest claim, never
    an assumption that the LLM pass ran.
    """
    tiers = report.get("kit", {}).get("tiers")
    tiers = tiers if isinstance(tiers, (list, tuple)) else []
    has_static, has_llm = sak_lib.TIER_STATIC in tiers, sak_lib.TIER_LLM in tiers
    if has_static and has_llm:
        return MODE_HYBRID
    if has_llm:
        return MODE_LLM
    return MODE_STATIC


def build_payload(report_path, wasm_path=""):
    """Compute the AttestationInput payload (the fields the registry's attest() expects).

    Refuses rather than emitting a payload with a missing anchor: the on-chain `attest` reverts
    on an empty source_hash (after the fee is locked), so building one converts a clear local
    error into a wasted transaction — or worse, into an agent's log line stating a mode before
    the failure. The artifact is permanent and unburnable; over-claiming is not a bad log line,
    it is an immutable one.
    """
    report = sak_lib.load_report(report_path)
    counts = sak_lib.severity_counts(report.get("findings", []))
    kit = report.get("kit", {})
    source = report.get("target", {}).get("source_hash", "")
    if not source:
        raise AttestationError(
            f"{report_path}: target.source_hash is empty — nothing to anchor the attestation to. "
            "Produce the report with ./audit.sh, or with sak_lib.build_report(findings, pkg_dir).")
    if not kit.get("version"):
        raise AttestationError(
            f"{report_path}: kit.version is missing — the report carries no provenance. "
            "An attestation must name the kit version that produced it.")
    return {
        "source_hash": source,
        "report_hash": _sha256_file(report_path),
        "wasm_hash": _sha256_file(wasm_path) if wasm_path else "",
        "kit_version": kit["version"],
        "checklist_version": kit.get("checklist_version", "unknown"),
        "mode": _derive_mode(report),
        "static_ruleset_version": str(kit.get("static_ruleset_version", "unknown")),
        "critical": _u16(counts.get("critical", 0)),
        "high": _u16(counts.get("high", 0)),
        "medium": _u16(counts.get("medium", 0)),
        "low": _u16(counts.get("low", 0)),
        "info": _u16(counts.get("info", 0)),
    }


_STR_FIELDS = ["source_hash", "report_hash", "wasm_hash", "kit_version", "checklist_version",
               "mode", "static_ruleset_version"]
_U16_FIELDS = ["critical", "high", "medium", "low", "info"]


def render_manifest(payload, component, account, fee="10"):
    """Render a Radix transaction manifest calling attest(AttestationInput) + depositing the NFT."""
    def quote(v):
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        s = s.replace("\n", " ").replace("\r", " ")  # no control chars in a manifest string literal
        return '"' + s + '"'

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
    ap.add_argument("--component", default="", help="deployed attestation registry component address")
    ap.add_argument("--account", default="", help="your account address (pays the fee, receives the NFT)")
    ap.add_argument("--out-manifest", default="", help="write the manifest to this file")
    ap.add_argument("--json", action="store_true", help="print the payload JSON (even if --component is given)")
    args = ap.parse_args()

    try:
        payload = build_payload(args.report, args.wasm)
    except AttestationError as exc:
        sys.stderr.write(f"::error::{exc}\n")
        return 2
    sys.stderr.write(f"[attest] mode {payload['mode']} · {payload['critical']}C/{payload['high']}H · "
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
