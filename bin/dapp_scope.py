#!/usr/bin/env python3
"""Dapp-scope pass: validate an operator questionnaire, render a report. First slice of
docs/DAPP-SCOPE-EXTENSION.md — see that doc's §5 for the design this implements.

The blueprint-source checklist (prompts/checklist.md) audits one Scrypto package. This
questionnaire (schema/dapp-scope-questionnaire.schema.json, prompts/dapp-scope-checklist.md)
covers everything around it that a source-only pass cannot see: data sources, listing/registry
config, admin powers, and operational response — plus, per listed input, the §3 cross-cutting
question ("if this one input takes its worst possible value, what's the loss cap?").

This is explicitly NOT wired into audit-report.schema.json, the L1-L4 attestation ladder, or the
MCP tools. Organizational fact goes stale in a way source doesn't, so this report carries its own
freshness marker (the questionnaire's `answered_at`) instead of a source_hash, and its own
schema_version/report_type so it can never be confused with, or silently claimed as, a
blueprint-source attestation (docs/attestation-levels.md).

An "unbounded" answer to the §3 question is itself a finding — never a silent field. Every such
answer across data_sources / listings / admin_powers becomes a `U-###` finding in the report.

Stdlib only. Real JSON-Schema validation runs when `jsonschema` is installed (`pip install
".[schema]"`); otherwise a hand-rolled structural check covers the same required-field and
per-surface rules so the tool still refuses a malformed questionnaire rather than failing open.
Importable + CLI (`sak-dapp-scope`).
"""
import argparse
import datetime
import json
import os
import re
import sys

try:  # installed: real submodule of the scrypto_audit_kit package
    from . import sak_lib
except ImportError:  # bare clone / direct script run: bin/ is itself on sys.path
    import sak_lib

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_INPUT_SURFACES = ("data_sources", "listings", "admin_powers")

_SURFACE_ITEM_REQUIRED = {
    "data_sources": ("name", "trust_model", "sanity_bound_exists", "max_loss"),
    "listings": ("asset_or_pair", "add_process_attributable", "reruns_original_checks", "max_loss"),
    "admin_powers": ("capability", "holder", "single_signature_sufficient", "max_loss"),
}
_TRUST_MODELS = {"single_oracle", "median_of_n", "twap", "operator_signed_message", "other"}
_HOLDER_TYPES = {"on_chain_badge", "off_chain_signer", "both"}
_FASTEST_LEVERS = {"pause", "redeploy", "governance_vote", "none", "other"}

_SURFACE_TITLES = {
    "data_sources": "2.1 Data sources",
    "listings": "2.2 Listing / registry configuration",
    "admin_powers": "2.3 Admin powers",
}


class DappScopeError(Exception):
    """Raised for a kit-side problem (missing schema, unreadable file) — not a bad questionnaire."""


def _kit_home():
    """Locate the kit's repo resources (schema/), same walk-up as bin/mcp_server.py's _kit_home."""
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


DEFAULT_SCHEMA_PATH = os.path.join(_kit_home(), "schema", "dapp-scope-questionnaire.schema.json")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_questionnaire(data, schema_path=None):
    """Return a list of human-readable error strings; empty means valid.

    Prefers real JSON-Schema validation (jsonschema, if installed) against the questionnaire
    schema. Falls back to a hand-rolled structural check (stdlib only) when jsonschema is
    absent, so the tool still meaningfully validates rather than treating "no dependency" as
    "no errors" — the analyzer not failing open is a standing invariant of this kit.
    """
    if not isinstance(data, dict):
        return ["<root>: questionnaire must be a JSON object"]

    schema_path = schema_path or DEFAULT_SCHEMA_PATH
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return _structural_validate(data)

    try:
        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
    except OSError as exc:
        raise DappScopeError(f"cannot load questionnaire schema at {schema_path}: {exc}") from exc

    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: [str(p) for p in e.path])
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]


def _structural_validate(data):
    errors = []
    for key in ("schema_version", "dapp_name", "answered_at", "data_sources", "listings",
                "admin_powers", "operational_response"):
        if key not in data:
            errors.append(f"<root>: missing required field '{key}'")

    if "schema_version" in data and data["schema_version"] != "1.0":
        errors.append('schema_version: must be "1.0"')
    if "dapp_name" in data and not str(data["dapp_name"]).strip():
        errors.append("dapp_name: must be a non-empty string")
    if "answered_at" in data and not _DATE_RE.match(str(data["answered_at"])):
        errors.append("answered_at: must be an ISO date YYYY-MM-DD")

    for surface in _INPUT_SURFACES:
        if surface in data:
            errors.extend(_validate_input_surface(surface, data[surface]))

    if "operational_response" in data:
        errors.extend(_validate_operational_response(data["operational_response"]))

    return errors


def _validate_max_loss(prefix, ml):
    errors = []
    if not isinstance(ml, dict):
        return [f"{prefix}.max_loss: must be an object"]
    if "bounded" not in ml:
        errors.append(f"{prefix}.max_loss: missing required field 'bounded'")
    elif not isinstance(ml["bounded"], bool):
        errors.append(f"{prefix}.max_loss.bounded: must be a boolean")
    if not str(ml.get("rationale", "")).strip():
        errors.append(f"{prefix}.max_loss: missing required field 'rationale' "
                       "(an 'unbounded' answer is itself a finding — say why)")
    if ml.get("bounded") is True and not str(ml.get("bound_description", "")).strip():
        errors.append(f"{prefix}.max_loss: bounded=true requires 'bound_description'")
    return errors


def _validate_input_surface(surface, block):
    if not isinstance(block, dict):
        return [f"{surface}: must be an object"]
    if "applicable" not in block:
        return [f"{surface}: missing required field 'applicable'"]
    if block["applicable"] is False:
        if not str(block.get("justification", "")).strip():
            return [f"{surface}: applicable=false requires a non-empty 'justification'"]
        return []
    if block["applicable"] is not True:
        return [f"{surface}.applicable: must be true or false"]

    errors = []
    items = block.get("items")
    if not isinstance(items, list) or not items:
        return [f"{surface}.items: required, non-empty array when applicable=true"]

    required = _SURFACE_ITEM_REQUIRED[surface]
    for i, item in enumerate(items):
        prefix = f"{surface}.items[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        for field in required:
            if field not in item:
                errors.append(f"{prefix}: missing required field '{field}'")
        if surface == "data_sources" and item.get("trust_model") not in _TRUST_MODELS | {None}:
            errors.append(f"{prefix}.trust_model: must be one of {sorted(_TRUST_MODELS)}")
        if surface == "admin_powers":
            if item.get("holder") not in _HOLDER_TYPES | {None}:
                errors.append(f"{prefix}.holder: must be one of {sorted(_HOLDER_TYPES)}")
            if item.get("single_signature_sufficient") is True and \
                    not str(item.get("accepted_risk_justification", "")).strip():
                errors.append(f"{prefix}: single_signature_sufficient=true requires "
                               "'accepted_risk_justification'")
        if "max_loss" in item:
            errors.extend(_validate_max_loss(prefix, item["max_loss"]))
    return errors


def _validate_operational_response(op):
    if not isinstance(op, dict):
        return ["operational_response: must be an object"]
    if "applicable" not in op:
        return ["operational_response: missing required field 'applicable'"]
    if op["applicable"] is False:
        if not str(op.get("justification", "")).strip():
            return ["operational_response: applicable=false requires a non-empty 'justification'"]
        return []
    if op["applicable"] is not True:
        return ["operational_response.applicable: must be true or false"]

    errors = []
    for field in ("pause_path_exists", "monitoring_exists", "escalation_defined", "fastest_lever"):
        if field not in op:
            errors.append(f"operational_response: missing required field '{field}'")
    if "fastest_lever" in op and op["fastest_lever"] not in _FASTEST_LEVERS:
        errors.append(f"operational_response.fastest_lever: must be one of {sorted(_FASTEST_LEVERS)}")
    return errors


# ---------------------------------------------------------------------------
# The unbounded-is-a-finding rule
# ---------------------------------------------------------------------------

def _item_label(surface, item):
    if surface == "data_sources":
        return item.get("name") or "unnamed data source"
    if surface == "listings":
        return item.get("asset_or_pair") or "unnamed listing"
    if surface == "admin_powers":
        return item.get("capability") or "unnamed admin power"
    return "unnamed item"


def find_unbounded_findings(data):
    """Every listed input across 2.1-2.3 whose max_loss.bounded is False is a finding (§3):
    'no bound exists' is the honest output on a system with no circuit breaker, not silence.

    Assumes `data` already passed validate_questionnaire — a malformed max_loss (missing
    'bounded') is a validation error, not scanned for here.
    """
    findings = []
    for surface in _INPUT_SURFACES:
        block = data.get(surface) or {}
        if not block.get("applicable"):
            continue
        for item in block.get("items") or []:
            if not isinstance(item, dict):
                continue
            ml = item.get("max_loss")
            if isinstance(ml, dict) and ml.get("bounded") is False:
                findings.append({
                    "surface": surface,
                    "item": _item_label(surface, item),
                    "rationale": ml.get("rationale", ""),
                })
    for n, f in enumerate(findings, start=1):
        f["id"] = f"U-{n:03d}"
    return findings


# ---------------------------------------------------------------------------
# Report building + rendering
# ---------------------------------------------------------------------------

def build_report(data, generated_at=None):
    """Turn a validated questionnaire into the dapp-scope report dict (rendered to md + json).

    Deliberately its own schema_version/report_type axis, not "1.0" of the audit report — a
    reader must never mistake this for schema/audit-report.schema.json output.
    """
    generated_at = generated_at or datetime.datetime.now(datetime.timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schema_version": "1.0",
        "report_type": "dapp-scope",
        "attested": False,
        "dapp_name": data.get("dapp_name", ""),
        "answered_at": data.get("answered_at", ""),
        "answered_by_role": data.get("answered_by_role", ""),
        "generated_at": generated_at,
        "kit_version": sak_lib.kit_version(),
        "surfaces": {
            "data_sources": data.get("data_sources"),
            "listings": data.get("listings"),
            "admin_powers": data.get("admin_powers"),
            "operational_response": data.get("operational_response"),
        },
        "unbounded_findings": find_unbounded_findings(data),
    }


def _render_max_loss(ml):
    if not isinstance(ml, dict):
        return "  - **Max loss:** (not answered)"
    if ml.get("bounded") is True:
        return (f"  - **Max loss:** bounded — {ml.get('bound_description', '')}\n"
                f"    _{ml.get('rationale', '')}_")
    return f"  - **Max loss:** **UNBOUNDED** — _{ml.get('rationale', '')}_"


def _render_input_surface(surface, block):
    title = _SURFACE_TITLES[surface]
    out = [f"## {title}", ""]
    if not block or not block.get("applicable"):
        justification = (block or {}).get("justification", "(no justification given)")
        out.append(f"**Not applicable** — {justification}")
        out.append("")
        return out
    for item in block.get("items") or []:
        out.append(f"### {_item_label(surface, item)}")
        if surface == "data_sources":
            out.append(f"- **Trust model:** {item.get('trust_model', '?')}"
                        + (f" — {item['trust_model_detail']}" if item.get("trust_model_detail") else ""))
            sb = "yes" if item.get("sanity_bound_exists") else "no"
            out.append(f"- **Sanity bound in consuming code:** {sb}"
                        + (f" — {item['sanity_bound_description']}" if item.get("sanity_bound_description") else ""))
        elif surface == "listings":
            out.append(f"- **Added by:** {item.get('added_by', '?')}")
            attributable = "yes" if item.get("add_process_attributable") else "no"
            reruns = "yes" if item.get("reruns_original_checks") else "no"
            out.append(f"- **Attributable on-chain:** {attributable}")
            out.append(f"- **Re-runs original checks:** {reruns}")
            if item.get("decimals_assumption_note"):
                out.append(f"- **Decimals note:** {item['decimals_assumption_note']}")
        elif surface == "admin_powers":
            out.append(f"- **Holder:** {item.get('holder', '?')}")
            single = "yes" if item.get("single_signature_sufficient") else "no"
            out.append(f"- **Single signature sufficient (no timelock/multisig):** {single}")
            if item.get("accepted_risk_justification"):
                out.append(f"- **Accepted-risk justification:** {item['accepted_risk_justification']}")
            if item.get("off_chain_holder_scope"):
                out.append(f"- **Off-chain holder scope:** {item['off_chain_holder_scope']}")
        out.append(_render_max_loss(item.get("max_loss")))
        out.append("")
    return out


def _render_operational_response(op):
    out = ["## 2.4 Operational response", ""]
    if not op or not op.get("applicable"):
        justification = (op or {}).get("justification", "(no justification given)")
        out.append(f"**Not applicable** — {justification}")
        out.append("")
        return out
    out.append(f"- **Pause/halt path exists:** {'yes' if op.get('pause_path_exists') else 'no'}"
                + (f" — trigger: {op['pause_who_can_trigger']}" if op.get("pause_who_can_trigger") else ""))
    out.append(f"- **Exercised outside a test:** {'yes' if op.get('pause_exercised_outside_test') else 'no'}")
    out.append(f"- **Monitoring exists:** {'yes' if op.get('monitoring_exists') else 'no'}"
                + (f" — covers: {', '.join(op.get('monitoring_covers', []))}" if op.get("monitoring_covers") else ""))
    if op.get("monitoring_description"):
        out.append(f"  - {op['monitoring_description']}")
    out.append(f"- **Escalation defined:** {'yes' if op.get('escalation_defined') else 'no'}"
                + (f" — {op['escalation_description']}" if op.get("escalation_description") else ""))
    out.append(f"- **Fastest lever available without a human audit / governance vote:** "
                f"{op.get('fastest_lever', '?')}")
    out.append("")
    return out


def render_markdown(report):
    """Render the report dict from build_report() as the markdown document."""
    out = [f"# Dapp-scope report: {report.get('dapp_name', '(unnamed)')}", ""]
    out.append(f"**Answered at:** {report.get('answered_at', '?')}"
               + (f" (by: {report['answered_by_role']})" if report.get("answered_by_role") else "")
               + " — organizational facts go stale: a listing added or an admin key rotated "
                 "after this date is not reflected below.")
    out.append(f"**Generated:** {report.get('generated_at', '?')} by scrypto-audit-kit "
               f"{report.get('kit_version', 'unknown')}.")
    out.append("")
    out.append("> **Not an attestation.** This report covers organizational fact, not source — it "
               "has no `source_hash`, is not scored under the kit's L1–L4 attestation ladder "
               "([docs/attestation-levels.md](../docs/attestation-levels.md)), and is not merged "
               "into the blueprint checklist or `schema/audit-report.schema.json`. See "
               "[docs/DAPP-SCOPE-EXTENSION.md](../docs/DAPP-SCOPE-EXTENSION.md) §4.")
    out.append("")

    surfaces = report.get("surfaces", {})
    for surface in _INPUT_SURFACES:
        out.extend(_render_input_surface(surface, surfaces.get(surface)))
    out.extend(_render_operational_response(surfaces.get("operational_response")))

    out.append("## Unbounded-loss findings (§3)")
    out.append("")
    findings = report.get("unbounded_findings", [])
    if not findings:
        out.append("No unbounded-loss findings — every listed input has a stated bound.")
    else:
        for f in findings:
            out.append(f"- **{f['id']}** — {f['surface']} / {f['item']}: **unbounded** — {f['rationale']}")
    out.append("")

    out.append("---")
    out.append("<!-- machine-readable: do not edit -->")
    out.append("```json")
    out.append(json.dumps(report, indent=2))
    out.append("```")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run(questionnaire_path, schema_path=None):
    """Load, validate, and build a report. Raises DappScopeError with a joined message on
    validation failure (never partially renders an invalid questionnaire)."""
    with open(questionnaire_path, encoding="utf-8") as fh:
        data = json.load(fh)
    errors = validate_questionnaire(data, schema_path=schema_path)
    if errors:
        raise DappScopeError("questionnaire failed validation:\n" + "\n".join(f"  - {e}" for e in errors))
    return build_report(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("questionnaire", help="path to the dapp-scope questionnaire (JSON)")
    ap.add_argument("--out", help="write the markdown report here (default: stdout)")
    ap.add_argument("--out-json", help="also write the structured report as JSON here")
    ap.add_argument("--schema", help="override path to the questionnaire JSON Schema (mostly for tests)")
    args = ap.parse_args()

    try:
        with open(args.questionnaire, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        print(f"error: cannot read {args.questionnaire}: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: {args.questionnaire} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    try:
        errors = validate_questionnaire(data, schema_path=args.schema)
    except DappScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("questionnaire failed validation:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    report = build_report(data)
    md = render_markdown(report)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
    else:
        sys.stdout.write(md)

    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")

    n = len(report["unbounded_findings"])
    print(f"[dapp-scope] {report['dapp_name']}: {n} unbounded-loss finding(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
