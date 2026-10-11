"""Check 2 -- owner role: securified/rotatable vs. fixed vs. OwnerRole::None/DenyAll.

**Read docs/posture-scanner.md#check-2-owner-role before touching this file.** This is the
check most prone to a wrong red: a naive owner-role rule would misjudge OwnerRole::None, which is
*correct* for a permissionless AMM pool.

The model. The Guild's own Badge Manager and Badge Factory (Protected/None) and dApp Definition
account (Protected/Object) are observed live in the published scan; the DenyAll/None and
Protected/Owner shapes are exercised by the fixtures in examples/posture-scanner/:

  rule.type=DenyAll            -> informational, ALWAYS. Permanently ownerless. Correct, common,
                                   deliberate design for a permissionless pool -- and structurally
                                   indistinguishable, from Gateway data alone, from "nobody set up
                                   a recovery path." The scanner does not guess which; it says so.
  rule.type=Protected,
    updater=None                -> informational. Fixed to one requirement forever, no rotation
                                   path if that badge is ever lost or compromised. Also common,
                                   also not provably wrong from chain data alone -- same
                                   discipline applied consistently, not just to the None case.
  rule.type=Protected,
    updater=Owner or Object     -> pass. Protected AND the badge holder (or the object's own
                                   self-securify path) can repoint the rule later. The one shape
                                   this check calls unambiguously good.
  rule.type=AllowAll            -> FAIL, critical. The one shape this check calls unambiguously
                                   bad: owner-gated authority requires no proof from anyone. This
                                   is provable from chain data alone, which is exactly why it is
                                   the sole case allowed to be a fail here -- see models.py's
                                   severity discipline docstring.
  anything else / malformed     -> informational. An unrecognized shape is a reason to say so,
                                   never a reason to guess.
"""
from .. import models, shapes

CHECK = "owner_role"


def check(entity, item, context):
    state_version = context["state_version"]
    owner = shapes.owner_role(item)

    if not owner or "rule" not in owner:
        return models.make_finding(
            CHECK, "informational", "informational",
            "No role_assignments.owner found on this entity -- cannot evaluate.",
            {"role_assignments.owner": owner}, state_version,
        )

    rule_type = owner.get("rule", {}).get("type")
    updater = owner.get("updater")
    evidence = {"role_assignments.owner.rule.type": rule_type, "role_assignments.owner.updater": updater}

    if rule_type == "DenyAll":
        return models.make_finding(
            CHECK, "informational", "informational",
            "Owner role is DenyAll (permanently ownerless, no updater can ever act). This is the "
            "correct, deliberate design for a permissionless component -- and, from chain data "
            "alone, indistinguishable from a project that never set up a recovery path. Severity "
            "intentionally not escalated: this check cannot determine intent.",
            evidence, state_version,
        )

    if rule_type == "Protected" and updater == "None":
        return models.make_finding(
            CHECK, "informational", "informational",
            "Owner role is protected by a fixed requirement with no rotation path (updater: "
            "None) -- if the required badge/key is ever lost or compromised, the owner rule can "
            "never be repointed. A common and often-intentional pattern; not provably wrong from "
            "chain data alone, so this stays informational rather than a guessed fail.",
            evidence, state_version,
        )

    if rule_type == "Protected" and updater in ("Owner", "Object"):
        return models.make_finding(
            CHECK, "pass", "none",
            f"Owner role is protected by a requirement AND rotatable (updater: {updater}) -- "
            f"the badge holder (or the object's own self-securify path) can repoint the owner "
            f"rule if it is ever compromised.",
            evidence, state_version,
        )

    if rule_type == "AllowAll":
        return models.make_finding(
            CHECK, "fail", "critical",
            "Owner role is AllowAll -- any account can exercise owner-gated authority with no "
            "proof required at all. Unlike DenyAll/Fixed, this is provably wrong regardless of "
            "the project's intent, not a judgment call.",
            evidence, state_version,
        )

    return models.make_finding(
        CHECK, "informational", "informational",
        f"Owner role has an unrecognized rule.type/updater combination "
        f"({rule_type!r}/{updater!r}) -- refusing to guess at severity for a shape this "
        f"check does not yet model.",
        evidence, state_version,
    )
