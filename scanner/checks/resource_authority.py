"""Check 3 -- resource authority: mint / burn / recall / freeze roles on a fungible resource.

Only meaningful for entity_kind == "resource" (a component/account/package has no minter/burner/
freezer/recaller role keys). The best-case shape, as in the resource_extern_b_token.json fixture:
minter/burner/freezer gated behind an issuer's badge (Protected); recaller AND recaller_updater
both DenyAll (recall is not just off, it can never be turned back on); depositor/withdrawer both
AllowAll (freely transferable, as expected for a token). Every scored role's `_updater`
counterpart is read too -- the role being closed today says nothing about whether it can be
silently opened later by whoever holds the updater.

## Why this check's DenyAll handling differs from Check 2's

Check 2 (owner_role.py) treats DenyAll as ambiguous-intent and never escalates it. This check
does NOT apply that same caution to minter/burner/freezer: there is no plausible reading of "this
resource can never be minted/burned/frozen by anyone" that is a problem for HOLDERS of the
resource -- unlike an absent owner (which can mean "nobody can ever recover/fix this," a
genuinely two-sided outcome), an absent minter only ever means supply cannot inflate, which is
monotonically safe. So DenyAll on minter/burner/freezer is `pass`, not `informational` -- a
deliberate difference from Check 2, not an inconsistency; see docs/posture-scanner.md#check-3.

recaller is scored more strictly: recall lets the resource's controller pull tokens out of ANY
holder's vault without their consent, so an OPEN recall path (now, or reachable later via its own
updater) is treated as the one directly fund-relevant fact this check can prove.
"""
from .. import models, shapes

CHECK = "resource_authority"

_SCORED_ROLES = ("minter", "burner", "freezer")
_CONTEXT_ROLES = ("depositor", "withdrawer")


def _resolve(entries, role_name):
    """Effective rule.type for one role key ('Main', role_name): the concrete rule.type string,
    "Owner" when it defers to the entity's own owner rule, or None if the role key is absent.
    """
    assignment = entries.get(("Main", role_name))
    if assignment is None:
        return None
    return shapes.explicit_rule_type(assignment)


def _score_mint_burn_freeze(role, rule_t):
    if rule_t == "AllowAll":
        return "fail", "critical", f"{role} is AllowAll -- anyone can {role} this resource with no proof required"
    return "pass", "none", f"{role} is {rule_t or 'unset'}"


def _score_recall(recall_t, recall_upd_t):
    if recall_t == "AllowAll":
        return "fail", "critical", "recaller is AllowAll -- any account can forcibly withdraw from ANY holder's vault right now"
    if recall_upd_t == "AllowAll":
        return "fail", "high", "recaller_updater is AllowAll -- anyone can grant themselves recall power even though it is closed today"
    if recall_t == "DenyAll" and recall_upd_t == "DenyAll":
        return "pass", "none", "recall is DenyAll and its updater is also DenyAll -- off, and cannot be turned on later"
    if recall_t == "DenyAll":
        return "informational", "informational", (
            "recall is currently DenyAll, but its updater is not DenyAll -- it could be reopened "
            "later; the scanner cannot assess who controls that without more context"
        )
    return "pass", "none", f"recall is {recall_t or 'unset'} (protected, not open)"


def check(entity, item, context):
    state_version = context["state_version"]

    if entity["entity_kind"] != "resource":
        return models.make_finding(
            CHECK, "not_applicable", "none",
            f"Not applicable: {entity['entity_kind']} entities carry no minter/burner/freezer/"
            f"recaller role keys (those are resource-manager-specific).",
            {"entity_kind": entity["entity_kind"]}, state_version,
        )

    entries = shapes.role_entries(item)
    evidence = {}
    findings = []  # (role, status, severity, detail)

    for role in _SCORED_ROLES:
        rule_t = _resolve(entries, role)
        updater_t = _resolve(entries, f"{role}_updater")
        evidence[f"role_assignments.{role}"] = rule_t
        evidence[f"role_assignments.{role}_updater"] = updater_t
        findings.append((role, *_score_mint_burn_freeze(role, rule_t)))

    recall_t = _resolve(entries, "recaller")
    recall_upd_t = _resolve(entries, "recaller_updater")
    evidence["role_assignments.recaller"] = recall_t
    evidence["role_assignments.recaller_updater"] = recall_upd_t
    findings.append(("recaller", *_score_recall(recall_t, recall_upd_t)))

    for role in _CONTEXT_ROLES:
        evidence[f"role_assignments.{role}"] = _resolve(entries, role)

    severity_rank = {s: i for i, s in enumerate(models.SEVERITIES)}
    worst_status, worst_severity = max(
        ((f[1], f[2]) for f in findings), key=lambda pair: severity_rank[pair[1]]
    )
    detail_text = "; ".join(f[3] for f in findings) + "."

    if worst_status == "fail":
        reason = "Provable authority misconfiguration: " + detail_text
    elif worst_status == "informational":
        reason = "No provable misconfiguration, but one role needs a caveat: " + detail_text
    else:
        reason = "No provable authority misconfiguration found: " + detail_text

    return models.make_finding(CHECK, worst_status, worst_severity, reason, evidence, state_version)
