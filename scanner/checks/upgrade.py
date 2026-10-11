"""Check 4 -- package/blueprint upgrade detected since the last scan.

A package's details carry details.vm_type, details.codes.items[].code_hash_hex (a WASM hash),
and details.blueprints.items[] = [{"name", "version"}] -- exactly the diffable pair a scanner
needs. A component carries a lighter-weight version of the same fact directly on its own
details (package_address, blueprint_name, blueprint_version) -- no second Gateway hop to the
package needed to track a component's own upgrade exposure.

This check cannot fire "changed" on a first scan by construction -- there is nothing to compare
against yet. That is not a bug to route around; it is reported plainly as the baseline case
(status=informational), so a reader never mistakes "no prior scan" for "confirmed unchanged".

An upgrade IS NOT treated as a `fail`: a code or blueprint-version change is a neutral,
noteworthy fact (routine improvement and a malicious swap look identical in this data), so a
detected change is `informational`/`medium` -- enough to surface prominently without asserting
wrongdoing the scanner cannot back up. See models.py's severity discipline note.

Not applicable to resource/account kinds -- neither carries upgradable code.
"""
from .. import models, shapes

CHECK = "package_upgrade"


def check(entity, item, context):
    state_version = context["state_version"]
    kind = entity["entity_kind"]

    if kind == "package":
        codes, blueprints = shapes.package_codes_and_blueprints(item)
        current = {"code_hash_hex": sorted(c for c in codes if c), "blueprints": blueprints}
    elif kind == "component":
        pkg_addr, bp_name, bp_version = shapes.package_address_and_blueprint(item)
        current = {"package_address": pkg_addr, "blueprint_name": bp_name, "blueprint_version": bp_version}
    else:
        return models.make_finding(
            CHECK, "not_applicable", "none",
            f"Not applicable: {kind} entities carry no upgradable code.",
            {"entity_kind": kind}, state_version,
        )

    baseline = context["baseline_evidence"](entity["id"])
    evidence = {**current, "baseline": baseline}

    if baseline is None:
        return models.make_finding(
            CHECK, "informational", "informational",
            "No prior scan exists to compare against -- this run establishes the baseline for "
            "future upgrade detection. A clean reading here is not yet a claim of 'unchanged'.",
            evidence, state_version,
        )

    if baseline == current:
        return models.make_finding(
            CHECK, "pass", "none",
            "No change in code_hash/blueprint version since the last scan.",
            evidence, state_version,
        )

    return models.make_finding(
        CHECK, "informational", "medium",
        "Package/blueprint changed since the last scan: " + _describe_change(baseline, current),
        evidence, state_version,
    )


def _describe_change(baseline, current):
    changed = []
    for key in sorted(set(baseline) | set(current)):
        if baseline.get(key) != current.get(key):
            changed.append(f"{key}: {baseline.get(key)!r} -> {current.get(key)!r}")
    return "; ".join(changed) if changed else "field set changed shape (see evidence)"
