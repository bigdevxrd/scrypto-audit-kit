"""Check 5 -- metadata claims vs reality.

The field shapes it reads (symbol/name/description/icon_url/info_url on a resource; name plus
fee-rate fields on a pool) are the ones captured in examples/posture-scanner/. Scope
decision, disclosed rather than silent: this check validates INTERNAL consistency only --
presence of the fields a reader would expect, and whether URL-shaped fields are actually typed
`Url` by the Gateway rather than a plain `String`. It does NOT fetch icon_url/info_url over the
network to confirm they resolve, and does NOT simulate a swap to check a claimed fee rate against
observed behavior -- both were floated as stretch ideas during scoping but never verified, and
this scanner does not ship a check it hasn't verified. See docs/posture-scanner.md#check-5 and
its "could not verify" list.

Nothing here is a provable security fail -- a missing icon or a String-typed URL is a labeling
gap, not a fund-safety fact -- so this check never returns `fail`; every non-clean result is
`informational`.
"""
from .. import models, shapes

CHECK = "metadata_claims"

# Fields a reader would reasonably expect for each entity kind, based on what was actually
# observed present on real, well-maintained entities during scoping (xUSDC has all six; the
# Guild's own accounts/components show the same pattern for name/description).
_EXPECTED_STRING_FIELDS_BY_KIND = {
    "account": ("name",),
    "component": ("name",),
    "resource": ("name", "symbol"),
    "package": (),  # not observed as a convention on any package read; not required
}
_URL_FIELDS = ("icon_url", "info_url")
_STRING_CONTEXT_FIELDS = ("name", "symbol", "description")


def check(entity, item, context):
    state_version = context["state_version"]
    kind = entity["entity_kind"]
    evidence = {}
    issues = []  # (severity, detail)

    for field in _STRING_CONTEXT_FIELDS:
        evidence[f"metadata.{field}"] = shapes.metadata_single(item, field)

    for field in _URL_FIELDS:
        typed = shapes.metadata_typed(item, field)
        evidence[f"metadata.{field}"] = typed.get("value") if typed else None
        if typed is not None and typed.get("type") != "Url":
            issues.append(("low", f"{field} is present but typed {typed.get('type')!r}, not 'Url'"))

    expected = _EXPECTED_STRING_FIELDS_BY_KIND.get(kind, ())
    missing = [f for f in expected if not evidence.get(f"metadata.{f}")]
    if missing:
        issues.append(("low", f"missing expected metadata field(s) for a {kind}: {missing}"))

    if not issues:
        return models.make_finding(
            CHECK, "pass", "none",
            "Metadata present and internally consistent: expected string fields are set, and any "
            "icon_url/info_url present is correctly typed as Url.",
            evidence, state_version,
        )

    severity_rank = {s: i for i, s in enumerate(models.SEVERITIES)}
    worst_severity = max((sev for sev, _ in issues), key=lambda s: severity_rank[s])
    reason = "Metadata gap(s): " + "; ".join(detail for _, detail in issues) + "."
    return models.make_finding(CHECK, "informational", worst_severity, reason, evidence, state_version)
