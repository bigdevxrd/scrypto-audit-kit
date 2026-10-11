"""Shared vocabulary for every check: statuses, severities, the Finding shape, and embargo.

Plain string constants, not enum.Enum -- consistent with the rest of the kit's stdlib-only,
hand-rolled-validation style (see bin/dapp_scope.py's _TRUST_MODELS/_HOLDER_TYPES).

## The severity discipline (read this before adding or editing a check)

`fail` + high/critical severity is reserved for shapes a check can PROVE are wrong from chain
data alone -- e.g. a mint role set to AllowAll. Every check must reach for `informational`
instead whenever the correct interpretation genuinely depends on the project's own intent (the
canonical example: OwnerRole::None is the *correct*, deliberate design for a permissionless AMM
pool, and indistinguishable from "nobody thought about recovery" using only what the Gateway
returns). Getting this backwards on a stranger's project is the one failure mode that ends this
program before it starts -- see docs/posture-scanner.md#check-2-owner-role.

`not_applicable` always carries severity `none`: a check that does not apply to this entity kind
is not a fact about the entity, so it cannot be concerning.
"""
import datetime

STATUSES = ("pass", "fail", "informational", "not_applicable")

# Ordered least -> most concerning. Index order is relied on by report.py's summary rollup.
SEVERITIES = ("none", "informational", "low", "medium", "high", "critical")

CHECKS = (
    "dapp_definition_two_way",
    "owner_role",
    "resource_authority",
    "package_upgrade",
    "metadata_claims",
)

ENTITY_KINDS = ("account", "component", "resource", "package")

# status -> the only severities that status is allowed to carry. Enforced by make_finding()
# so a check cannot silently drift into "informational status, critical severity" (which would
# defeat the whole point of the informational floor) or "fail status, none severity" (a fail
# that alarms nobody).
_ALLOWED_SEVERITIES_FOR_STATUS = {
    "pass": ("none",),
    "not_applicable": ("none",),
    "informational": ("informational", "low", "medium"),
    "fail": ("low", "medium", "high", "critical"),
}


class CheckContractError(Exception):
    """Raised when a check tries to emit a status/severity pairing the contract forbids.

    This is a bug in the check's own code, not a finding about the scanned entity -- it must
    never be caught and downgraded to a finding. Fail loud, in CI, before the bad pairing ever
    reaches a report.json a public page would render.
    """


def public_embargo():
    """The default embargo block: public, immediate. See docs/posture-scanner.md#embargo.

    All five posture checks report STATED CONFIGURATION -- what a role or metadata field is
    currently set to -- never a derived exploit path, so every finding from them publishes
    immediately. This function is the only place that default lives, so every check calls it
    rather than inlining the dict.
    """
    return {"status": "public", "publish_at": None, "reason": None}


def embargoed(reason, publish_at):
    """An embargoed finding: exists for a future check that derives a real exploit path (e.g. a
    working drain manifest), not used by any of the five checks shipping today. `publish_at`
    must be an ISO-8601 UTC string ('...Z' or '+00:00').
    """
    if not reason or not publish_at:
        raise CheckContractError("embargoed() requires both a reason and a publish_at clock")
    return {"status": "embargoed", "publish_at": publish_at, "reason": reason}


def is_public(check):
    """A check publishes its `reason`/`evidence` only when its embargo block says `public`.

    The single embargo predicate every renderer that emits a check's detail must call --
    `scanner.report.render_markdown` and `scanner.site.render_html`/`redact_for_publication`
    all import this rather than each hand-rolling the same `dict.get` chain, so the rule can't
    drift between renderers. Defensive on purpose: a check missing the `embargo` block entirely,
    or carrying a malformed one, is treated as held, not public -- failing closed is the only
    safe default for a field that gates a finding's disclosure.
    """
    embargo = check.get("embargo")
    if not isinstance(embargo, dict):
        return False
    return embargo.get("status") == "public"


# The text every renderer substitutes for a held check's `reason`/`evidence` instead of the
# real value. One canonical pair, not one string per renderer, so `redact_for_publication`'s
# JSON output and `render_markdown`'s defense-in-depth substitution can never say something
# different about the same held finding. `HELD_EVIDENCE` is a non-empty dict, not `{}`, because
# the schema requires `evidence` to carry at least one field.
HELD_REASON = (
    "Detail is held under embargo. Only this check's name, status and severity are published "
    "until the disclosure clock in its embargo.publish_at is reached."
)
HELD_EVIDENCE = {"embargo": "evidence withheld pending disclosure"}

# The text every renderer substitutes for a PUBLIC check's `reason`/`evidence` when the name
# screen (scanner.site's withheld-entity needle scan over a published entity's own check text)
# finds a withheld third party's name inside it. Distinct from HELD_REASON/HELD_EVIDENCE above:
# this check was never under embargo -- its own `embargo.status` stays "public" and its
# `status`/`severity` are untouched -- the substitution exists because free text on a
# published entity's own check (`reason`, and `evidence`'s Gateway-sourced values) can echo a
# third party's name even though the check itself belongs to us. See
# scanner.site.redact_for_publication's rule 4.
NAME_SCREEN_REASON = (
    "Detail is withheld: this check's own reason/evidence text referenced a project this "
    "report does not publish. The finding's check, status and severity are unaffected."
)
NAME_SCREEN_EVIDENCE = {"name_screen": "evidence withheld: referenced a project this report does not publish"}


def redact_embargo(embargo):
    """The embargo block a held check's `embargo` field is replaced with for publication.

    `embargo.reason` is not decoration -- the schema's own example for it is "describes a
    working fund-extraction path", the exact sentence `HELD_REASON` exists to keep off a
    public page. A held check's `reason`/`evidence` get redacted for precisely this danger;
    `embargo.reason` is the same danger one key deeper, and passes straight through a naive
    `deepcopy` if nothing touches it. `status` and `publish_at` are kept -- `render_html`'s
    disclosure-clock line needs `publish_at`, and `status` is already public via `is_public`
    itself. `reason` becomes `None` rather than being dropped: the schema requires the key
    (`additionalProperties: false`, `reason` required) but allows a `null` value, which is
    already what a `public` embargo carries for "nothing to say" -- the same honest value
    fits a held one too. Defensive on the input like `is_public`: a non-dict/malformed
    embargo redacts to an all-held placeholder instead of raising or passing anything
    through, since a check missing/mangling its own embargo block is the last place a real
    reason should leak through by accident.
    """
    if not isinstance(embargo, dict):
        return {"status": "embargoed", "publish_at": None, "reason": None}
    return {
        "status": embargo.get("status", "embargoed"),
        "publish_at": embargo.get("publish_at"),
        "reason": None,
    }


def make_finding(check, status, severity, reason, evidence, state_version, embargo=None):
    """Build one check_result dict matching schema/posture-scan-report.schema.json's $defs.check_result.

    Validates the check name, status/severity vocabulary, and the status->severity contract
    above before returning -- a check that violates the contract raises CheckContractError
    rather than silently producing a report a public page would render wrong.
    """
    if check not in CHECKS:
        raise CheckContractError(f"unknown check name: {check!r}")
    if status not in STATUSES:
        raise CheckContractError(f"unknown status: {status!r}")
    if severity not in SEVERITIES:
        raise CheckContractError(f"unknown severity: {severity!r}")
    allowed = _ALLOWED_SEVERITIES_FOR_STATUS[status]
    if severity not in allowed:
        raise CheckContractError(
            f"{check}: status={status!r} may not carry severity={severity!r} "
            f"(allowed: {allowed}) -- see models.py's severity discipline note"
        )
    if not reason or not reason.strip():
        raise CheckContractError(f"{check}: reason must be a non-empty, human-readable string")
    if not isinstance(evidence, dict) or not evidence:
        raise CheckContractError(f"{check}: evidence must be a non-empty dict of the fields actually read")

    return {
        "check": check,
        "status": status,
        "severity": severity,
        "reason": reason,
        "evidence": evidence,
        "embargo": embargo if embargo is not None else public_embargo(),
        "state_version": state_version,
    }


def utcnow_iso():
    """UTC now as an ISO-8601 'Z'-suffixed string, second precision -- used for generated_at and
    as the default publish_at basis. Not a ledger timestamp; see gateway.py for that.
    """
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
