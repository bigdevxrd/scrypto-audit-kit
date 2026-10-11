"""Check 1 -- dApp-definition two-way verification.

Radix's convention: a component/resource/package names a dApp Definition account via a
`dapp_definition` (singular, GlobalAddress) or `dapp_definitions` (plural, GlobalAddressArray)
metadata key; that account, in turn, is expected to list the entity back in its own
`claimed_entities` (GlobalAddressArray) metadata. A one-sided claim -- in EITHER direction -- is
the finding: "A half-pair is NOT verification" (the check's guiding rule; see
docs/posture-scanner.md#check-1).

Both metadata key spellings are part of the Radix convention and are entity-kind-dependent (a
component carries the singular form, a fungible resource the plural) -- this check reads both.
"""
from .. import models, shapes

CHECK = "dapp_definition_two_way"


def check(entity, item, context):
    """context must carry:
      - related_lookup(address) -> item dict or None  (resolve an account this entity claims)
      - known_hubs: {address: item} for every dApp-Definition account fetched this run
      - state_version: int
    """
    state_version = context["state_version"]
    address = entity["address"]

    if entity.get("role") == "dapp_definition_hub":
        return _check_hub(item, state_version)
    return _check_claimant(entity, item, context, state_version)


def _check_hub(item, state_version):
    account_type = shapes.metadata_single(item, "account_type")
    claimed = shapes.metadata_array(item, "claimed_entities") or []
    evidence = {
        "metadata.account_type": account_type,
        "metadata.claimed_entities.count": len(claimed),
    }

    if account_type == "dapp definition" and claimed:
        return models.make_finding(
            CHECK, "pass", "none",
            f"Valid dApp Definition account: account_type is 'dapp definition' and it claims "
            f"{len(claimed)} entities back. Each claiming entity's own two-way status is "
            f"evaluated at that entity's own cohort row, not repeated here.",
            evidence, state_version,
        )
    if account_type == "dapp definition":
        return models.make_finding(
            CHECK, "fail", "low",
            "account_type is 'dapp definition' but claimed_entities is empty -- declared as a "
            "dApp Definition account but claims nothing back.",
            evidence, state_version,
        )
    return models.make_finding(
        CHECK, "informational", "informational",
        f"Cohort entry is tagged as a dApp Definition hub, but its account_type metadata does "
        f"not confirm it (got: {account_type!r}).",
        evidence, state_version,
    )


def _check_claimant(entity, item, context, state_version):
    address = entity["address"]
    single = shapes.metadata_single(item, "dapp_definition")
    array = shapes.metadata_array(item, "dapp_definitions") or []
    claims = []
    for c in ([single] if single else []) + list(array):
        if c and c not in claims:
            claims.append(c)

    if not claims:
        return _check_zero_sided(address, context, state_version)

    related_lookup = context["related_lookup"]
    verified_by, unreachable, no_back_ref = [], [], []
    for acct_addr in claims:
        acct_item = related_lookup(acct_addr)
        if acct_item is None:
            unreachable.append(acct_addr)
            continue
        back = shapes.metadata_array(acct_item, "claimed_entities") or []
        (verified_by if address in back else no_back_ref).append(acct_addr)

    evidence = {
        "metadata.dapp_definition(s)": claims,
        "back_reference_status": {
            **{a: "confirmed" for a in verified_by},
            **{a: "no_back_reference" for a in no_back_ref},
            **{a: "unreachable" for a in unreachable},
        },
    }

    if verified_by:
        return models.make_finding(
            CHECK, "pass", "none",
            f"Two-way verified: entity names {verified_by[0]} as its dApp Definition, and that "
            f"account's claimed_entities lists this entity back.",
            evidence, state_version,
        )
    if no_back_ref:
        return models.make_finding(
            CHECK, "fail", "medium",
            f"Half-pair: entity names {no_back_ref[0]} as its dApp Definition, but that "
            f"account's claimed_entities does not list this entity back. A one-sided claim is "
            f"not verification.",
            evidence, state_version,
        )
    return models.make_finding(
        CHECK, "informational", "informational",
        f"Entity names {unreachable[0]} as its dApp Definition, but the scanner could not fetch "
        f"that account this run to confirm the back-reference.",
        evidence, state_version,
    )


def _check_zero_sided(address, context, state_version):
    known_hubs = context["known_hubs"]
    reverse_claimants = [
        hub_addr for hub_addr, hub_item in known_hubs.items()
        if address in (shapes.metadata_array(hub_item, "claimed_entities") or [])
    ]
    if reverse_claimants:
        return models.make_finding(
            CHECK, "fail", "medium",
            f"Half-pair (reverse direction): entity does not name a dApp Definition itself, but "
            f"{reverse_claimants[0]} lists this entity in its own claimed_entities. Being claimed "
            f"is not the same as claiming back.",
            {"metadata.dapp_definition(s)": None, "reverse_claimed_by": reverse_claimants},
            state_version,
        )
    return models.make_finding(
        CHECK, "fail", "medium",
        "Does not name a dApp Definition at all (no 'dapp_definition' or 'dapp_definitions' "
        "metadata key), and is not listed by any dApp Definition account this scan knows "
        "about -- zero-sided, not just unverified.",
        {"metadata.dapp_definition(s)": None, "reverse_claimed_by": []},
        state_version,
    )
