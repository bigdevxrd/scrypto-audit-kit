"""Unit tests for the five posture checks (scanner/checks/*.py).

Every fixture in examples/posture-scanner/ is a trimmed capture of a pinned
/state/entity/details response with the identifying values replaced (third-party addresses are
synthetic -- see examples/posture-scanner/README.md; docs/posture-scanner.md has the
live-verification log), so the structure is faithful and nothing here invents a Gateway response
shape. Where a branch has no real example in the
verified cohort (e.g. an AllowAll owner role -- not something any project in this first cohort
actually does), the test says so explicitly and builds a minimal synthetic item.

No network calls anywhere in this file.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanner.checks import dapp_definition, metadata, owner_role, resource_authority, upgrade  # noqa: E402

FIXTURES = os.path.join(ROOT, "examples", "posture-scanner")


def load_item(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)["items"][0]


def ctx(state_version=557840622, related_lookup=None, known_hubs=None, baseline_evidence=None):
    return {
        "state_version": state_version,
        "related_lookup": related_lookup or (lambda addr: None),
        "known_hubs": known_hubs or {},
        "baseline_evidence": baseline_evidence or (lambda entity_id: None),
    }


def entity(id, project, category, address, entity_kind, label, role=None):
    e = {"id": id, "project": project, "category": category, "address": address,
         "entity_kind": entity_kind, "label": label}
    if role:
        e["role"] = role
    return e


# ---------------------------------------------------------------------------
# Check 1 -- dApp-definition two-way verification
# ---------------------------------------------------------------------------
class TestDappDefinitionCheck(unittest.TestCase):
    def setUp(self):
        self.extern_a_pool = load_item("component_extern_a_pool.json")
        self.extern_a_pkg = load_item("package_extern_a.json")
        self.extern_a_hub = load_item("account_extern_a_dapp_definition.json")
        self.extern_b_hub = load_item("account_extern_b_dapp_definition.json")
        self.extern_b_token = load_item("resource_extern_b_token.json")
        self.guild_hub = load_item("account_guild_dapp_definition.json")
        self.badge_manager = load_item("component_guild_badge_manager.json")
        self.badge_factory = load_item("component_guild_badge_factory.json")
        self.extern_c_pool = load_item("component_extern_c_pool.json")

    def test_external_pool_is_a_half_pair_fail(self):
        # Real, live-verified: the pool names its own dApp Definition account, but that
        # account's claimed_entities does NOT list the pool back.
        e = entity("extern-a-pool", "External A", "external", self.extern_a_pool["address"], "component", "Pool")
        related = {self.extern_a_hub["address"]: self.extern_a_hub}
        f = dapp_definition.check(e, self.extern_a_pool, ctx(related_lookup=related.get))
        self.assertEqual(f["status"], "fail")
        self.assertEqual(f["severity"], "medium")
        self.assertIn("Half-pair", f["reason"])
        self.assertEqual(f["embargo"]["status"], "public")

    def test_external_package_is_also_a_half_pair_fail(self):
        e = entity("extern-a-package", "External A", "external", self.extern_a_pkg["address"], "package", "Package")
        related = {self.extern_a_hub["address"]: self.extern_a_hub}
        f = dapp_definition.check(e, self.extern_a_pkg, ctx(related_lookup=related.get))
        self.assertEqual(f["status"], "fail")
        self.assertIn("Half-pair", f["reason"])

    def test_bridged_token_is_two_way_verified_pass(self):
        # Real, live-verified: the bridged token names its issuing account, and that account's
        # claimed_entities DOES list the token back.
        e = entity("extern-b-token", "External B", "external", self.extern_b_token["address"], "resource", "Bridged Token")
        related = {self.extern_b_hub["address"]: self.extern_b_hub}
        f = dapp_definition.check(e, self.extern_b_token, ctx(related_lookup=related.get))
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["severity"], "none")
        self.assertIn("Two-way verified", f["reason"])

    def test_unclaimed_pool_is_zero_sided_fail_when_no_hub_claims_it(self):
        # Real, live-verified: this pool has no dapp_definition/dapp_definitions metadata key at
        # all, and (per this test's known_hubs, built from the real hubs this scan fetched) is
        # not claimed by any of them either.
        e = entity("extern-c-pool", "External C", "external", self.extern_c_pool["address"], "component", "Pool")
        known_hubs = {self.guild_hub["address"]: self.guild_hub, self.extern_a_hub["address"]: self.extern_a_hub}
        f = dapp_definition.check(e, self.extern_c_pool, ctx(known_hubs=known_hubs))
        self.assertEqual(f["status"], "fail")
        self.assertEqual(f["severity"], "medium")
        self.assertIn("zero-sided", f["reason"])

    def test_guild_badge_manager_is_zero_sided_fail(self):
        # Real, live-verified: no dapp_definition claim, AND not present in the Guild's own hub's
        # claimed_entities -- a genuine double-absence, not just "unverified."
        e = entity("guild-badge-manager", "Radix Guild", "guild", self.badge_manager["address"], "component", "Badge Manager")
        known_hubs = {self.guild_hub["address"]: self.guild_hub}
        f = dapp_definition.check(e, self.badge_manager, ctx(known_hubs=known_hubs))
        self.assertEqual(f["status"], "fail")
        self.assertIn("zero-sided", f["reason"])
        self.assertEqual(f["reason"].count("Half-pair"), 0)

    def test_guild_badge_factory_is_reverse_half_pair_fail(self):
        # Real, live-verified: Badge Factory itself makes NO claim, but the Guild's own hub DOES
        # list it in claimed_entities -- the opposite asymmetry from Badge Manager, and this
        # check must tell the two apart, not lump them into one generic "fail".
        e = entity("guild-badge-factory", "Radix Guild", "guild", self.badge_factory["address"], "component", "Badge Factory")
        known_hubs = {self.guild_hub["address"]: self.guild_hub}
        f = dapp_definition.check(e, self.badge_factory, ctx(known_hubs=known_hubs))
        self.assertEqual(f["status"], "fail")
        self.assertIn("reverse direction", f["reason"])
        self.assertIn(self.guild_hub["address"], f["evidence"]["reverse_claimed_by"])

    def test_guild_hub_itself_passes_as_a_valid_dapp_definition_account(self):
        e = entity("guild-hub", "Radix Guild", "guild", self.guild_hub["address"], "account",
                   "Guild dApp Definition", role="dapp_definition_hub")
        f = dapp_definition.check(e, self.guild_hub, ctx())
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["severity"], "none")

    def test_hub_role_with_wrong_account_type_is_informational(self):
        fake_item = {"address": "account_rdx1fake", "metadata": {"items": []}, "details": {}}
        e = entity("fake-hub", "Nobody", "external", "account_rdx1fake", "account", "Not really a hub",
                   role="dapp_definition_hub")
        f = dapp_definition.check(e, fake_item, ctx())
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "informational")

    def test_unreachable_claimed_account_is_informational_not_a_guess(self):
        # Same pool, but this run's related_lookup could not fetch the claimed hub (e.g. a
        # transient Gateway failure on the second hop) -- must not be silently scored as a fail.
        e = entity("extern-a-pool", "External A", "external", self.extern_a_pool["address"], "component", "Pool")
        f = dapp_definition.check(e, self.extern_a_pool, ctx(related_lookup=lambda addr: None))
        self.assertEqual(f["status"], "informational")
        self.assertIn("could not fetch", f["reason"])


# ---------------------------------------------------------------------------
# Check 2 -- owner role
# ---------------------------------------------------------------------------
class TestOwnerRoleCheck(unittest.TestCase):
    def setUp(self):
        self.extern_a_pool = load_item("component_extern_a_pool.json")
        self.badge_manager = load_item("component_guild_badge_manager.json")
        self.extern_b_token = load_item("resource_extern_b_token.json")
        self.guild_hub = load_item("account_guild_dapp_definition.json")

    def test_denyall_owner_none_is_informational_not_red(self):
        """THE required case: OwnerRole::None on a real permissionless pool (rule.type=DenyAll,
        updater=None) must never be flagged red. This is the
        exact failure mode this check exists to avoid.
        """
        e = entity("extern-a-pool", "External A", "external", self.extern_a_pool["address"], "component", "Pool")
        f = owner_role.check(e, self.extern_a_pool, ctx())
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "informational")
        self.assertNotIn(f["severity"], ("high", "critical"))
        self.assertNotEqual(f["status"], "fail")

    def test_protected_fixed_none_updater_is_informational(self):
        # Real: Guild Badge Manager -- Protected + updater None. Same restraint as DenyAll:
        # not provably wrong from chain data alone.
        e = entity("guild-badge-manager", "Radix Guild", "guild", self.badge_manager["address"], "component", "Badge Manager")
        f = owner_role.check(e, self.badge_manager, ctx())
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "informational")

    def test_protected_owner_updater_is_pass(self):
        # Real: a bridged token's resource manager -- Protected + updater Owner (rotatable).
        e = entity("extern-b-token", "External B", "external", self.extern_b_token["address"], "resource", "Bridged Token")
        f = owner_role.check(e, self.extern_b_token, ctx())
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["severity"], "none")

    def test_protected_object_updater_is_pass(self):
        # Real: the Guild's own dApp Definition account -- Protected + updater Object
        # (self-securify path). A third real pattern, distinct from Owner but equally rotatable.
        e = entity("guild-hub", "Radix Guild", "guild", self.guild_hub["address"], "account", "Guild hub",
                    role="dapp_definition_hub")
        f = owner_role.check(e, self.guild_hub, ctx())
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["severity"], "none")

    def test_allowall_owner_is_a_provable_critical_fail(self):
        # No project in this cohort actually does this -- synthetic, to prove the one shape this
        # check DOES call unambiguously bad still gets caught.
        item = {"address": "component_rdx1synthetic", "metadata": {"items": []},
                "details": {"role_assignments": {"owner": {"rule": {"type": "AllowAll"}, "updater": "None"}}}}
        e = entity("synthetic-allowall", "Synthetic", "external", "component_rdx1synthetic", "component", "Synthetic")
        f = owner_role.check(e, item, ctx())
        self.assertEqual(f["status"], "fail")
        self.assertEqual(f["severity"], "critical")

    def test_missing_owner_role_is_informational(self):
        item = {"address": "component_rdx1synthetic", "metadata": {"items": []}, "details": {}}
        e = entity("synthetic-none", "Synthetic", "external", "component_rdx1synthetic", "component", "Synthetic")
        f = owner_role.check(e, item, ctx())
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "informational")

    def test_unrecognized_shape_is_informational_not_a_guess(self):
        item = {"address": "component_rdx1synthetic", "metadata": {"items": []},
                "details": {"role_assignments": {"owner": {"rule": {"type": "SomeFutureRuleType"}, "updater": "Weird"}}}}
        e = entity("synthetic-weird", "Synthetic", "external", "component_rdx1synthetic", "component", "Synthetic")
        f = owner_role.check(e, item, ctx())
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "informational")


# ---------------------------------------------------------------------------
# Check 3 -- resource authority
# ---------------------------------------------------------------------------
class TestResourceAuthorityCheck(unittest.TestCase):
    def setUp(self):
        self.extern_b_token = load_item("resource_extern_b_token.json")
        self.extern_a_pool = load_item("component_extern_a_pool.json")

    def test_not_applicable_to_components(self):
        e = entity("extern-a-pool", "External A", "external", self.extern_a_pool["address"], "component", "Pool")
        f = resource_authority.check(e, self.extern_a_pool, ctx())
        self.assertEqual(f["status"], "not_applicable")
        self.assertEqual(f["severity"], "none")

    def test_bridged_token_passes_clean(self):
        # Real: minter/burner/freezer Protected; recaller + recaller_updater both DenyAll
        # (permanently off); depositor/withdrawer AllowAll (expected for a bridge token).
        e = entity("extern-b-token", "External B", "external", self.extern_b_token["address"], "resource", "Bridged Token")
        f = resource_authority.check(e, self.extern_b_token, ctx())
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["severity"], "none")
        self.assertEqual(f["evidence"]["role_assignments.minter"], "Protected")
        self.assertEqual(f["evidence"]["role_assignments.recaller"], "DenyAll")
        self.assertEqual(f["evidence"]["role_assignments.recaller_updater"], "DenyAll")
        self.assertEqual(f["evidence"]["role_assignments.depositor"], "AllowAll")

    def _resource_item(self, overrides):
        entries = [
            {"role_key": {"module": "Main", "name": "minter"}, "assignment": {"explicit_rule": {"type": "Protected"}, "resolution": "Explicit"}},
            {"role_key": {"module": "Main", "name": "burner"}, "assignment": {"explicit_rule": {"type": "Protected"}, "resolution": "Explicit"}},
            {"role_key": {"module": "Main", "name": "freezer"}, "assignment": {"explicit_rule": {"type": "Protected"}, "resolution": "Explicit"}},
            {"role_key": {"module": "Main", "name": "recaller"}, "assignment": {"explicit_rule": {"type": "DenyAll"}, "resolution": "Explicit"}},
            {"role_key": {"module": "Main", "name": "recaller_updater"}, "assignment": {"explicit_rule": {"type": "DenyAll"}, "resolution": "Explicit"}},
        ]
        by_role = {(e["role_key"]["module"], e["role_key"]["name"]): e for e in entries}
        for (module, name), rule_type in overrides.items():
            by_role[(module, name)] = {"role_key": {"module": module, "name": name},
                                        "assignment": {"explicit_rule": {"type": rule_type}, "resolution": "Explicit"}}
        return {"address": "resource_rdx1synthetic", "metadata": {"items": []},
                "details": {"role_assignments": {"entries": list(by_role.values())}}}

    def test_allowall_minter_is_critical_fail(self):
        item = self._resource_item({("Main", "minter"): "AllowAll"})
        e = entity("synthetic", "Synthetic", "external", "resource_rdx1synthetic", "resource", "Synthetic")
        f = resource_authority.check(e, item, ctx())
        self.assertEqual(f["status"], "fail")
        self.assertEqual(f["severity"], "critical")
        self.assertIn("minter", f["reason"])

    def test_allowall_recaller_is_critical_fail(self):
        item = self._resource_item({("Main", "recaller"): "AllowAll"})
        e = entity("synthetic", "Synthetic", "external", "resource_rdx1synthetic", "resource", "Synthetic")
        f = resource_authority.check(e, item, ctx())
        self.assertEqual(f["status"], "fail")
        self.assertEqual(f["severity"], "critical")
        self.assertIn("recaller is AllowAll", f["reason"])

    def test_allowall_recaller_updater_alone_is_high_fail(self):
        # recall itself is closed, but anyone could grant themselves recall power later.
        item = self._resource_item({("Main", "recaller_updater"): "AllowAll"})
        e = entity("synthetic", "Synthetic", "external", "resource_rdx1synthetic", "resource", "Synthetic")
        f = resource_authority.check(e, item, ctx())
        self.assertEqual(f["status"], "fail")
        self.assertEqual(f["severity"], "high")

    def test_recall_deniable_reopenable_is_informational(self):
        item = self._resource_item({("Main", "recaller_updater"): "Protected"})
        e = entity("synthetic", "Synthetic", "external", "resource_rdx1synthetic", "resource", "Synthetic")
        f = resource_authority.check(e, item, ctx())
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "informational")

    def test_denyall_mint_burn_freeze_is_pass_not_ambiguous(self):
        # Unlike owner_role's treatment of DenyAll, a resource that can never mint/burn/freeze
        # again is straightforwardly safe, not ambiguous -- see this module's docstring.
        item = self._resource_item({("Main", "minter"): "DenyAll", ("Main", "burner"): "DenyAll", ("Main", "freezer"): "DenyAll"})
        e = entity("synthetic", "Synthetic", "external", "resource_rdx1synthetic", "resource", "Synthetic")
        f = resource_authority.check(e, item, ctx())
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["severity"], "none")


# ---------------------------------------------------------------------------
# Check 4 -- package/blueprint upgrade
# ---------------------------------------------------------------------------
class TestUpgradeCheck(unittest.TestCase):
    def setUp(self):
        self.extern_a_pkg = load_item("package_extern_a.json")
        self.extern_a_pool = load_item("component_extern_a_pool.json")
        self.extern_b_token = load_item("resource_extern_b_token.json")

    def test_not_applicable_to_resources(self):
        e = entity("extern-b-token", "External B", "external", self.extern_b_token["address"], "resource", "Bridged Token")
        f = upgrade.check(e, self.extern_b_token, ctx())
        self.assertEqual(f["status"], "not_applicable")
        self.assertEqual(f["severity"], "none")

    def test_package_first_scan_is_informational_baseline(self):
        e = entity("extern-a-package", "External A", "external", self.extern_a_pkg["address"], "package", "Package")
        f = upgrade.check(e, self.extern_a_pkg, ctx(baseline_evidence=lambda entity_id: None))
        self.assertEqual(f["status"], "informational")
        self.assertIn("baseline", f["reason"])
        self.assertIsNone(f["evidence"]["baseline"])
        self.assertEqual(f["evidence"]["code_hash_hex"], ["2678bfc35cd9092e17cb15577fcd41d2abed92e43885e83f6a06c18ad7519937"])

    def test_component_first_scan_is_informational_baseline(self):
        e = entity("extern-a-pool", "External A", "external", self.extern_a_pool["address"], "component", "Pool")
        f = upgrade.check(e, self.extern_a_pool, ctx(baseline_evidence=lambda entity_id: None))
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["evidence"]["blueprint_version"], "1.0.0")

    def test_package_unchanged_since_baseline_is_pass(self):
        e = entity("extern-a-package", "External A", "external", self.extern_a_pkg["address"], "package", "Package")
        baseline = {"code_hash_hex": ["2678bfc35cd9092e17cb15577fcd41d2abed92e43885e83f6a06c18ad7519937"],
                    "blueprints": {"Pool": "1.0.0"}}
        f = upgrade.check(e, self.extern_a_pkg, ctx(baseline_evidence=lambda entity_id: baseline))
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["severity"], "none")

    def test_package_changed_since_baseline_is_informational_medium(self):
        # A change is a neutral, noteworthy fact -- never asserted as wrongdoing by this check.
        e = entity("extern-a-package", "External A", "external", self.extern_a_pkg["address"], "package", "Package")
        baseline = {"code_hash_hex": ["deadbeef00000000000000000000000000000000000000000000000000000"],
                    "blueprints": {"Pool": "0.9.0"}}
        f = upgrade.check(e, self.extern_a_pkg, ctx(baseline_evidence=lambda entity_id: baseline))
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "medium")
        self.assertIn("changed since the last scan", f["reason"])
        self.assertNotEqual(f["status"], "fail")


# ---------------------------------------------------------------------------
# Check 5 -- metadata claims vs reality
# ---------------------------------------------------------------------------
class TestMetadataCheck(unittest.TestCase):
    def setUp(self):
        self.extern_b_token = load_item("resource_extern_b_token.json")
        self.badge_manager = load_item("component_guild_badge_manager.json")
        self.extern_a_pkg = load_item("package_extern_a.json")

    def test_bridged_token_passes_clean(self):
        e = entity("extern-b-token", "External B", "external", self.extern_b_token["address"], "resource", "Bridged Token")
        f = metadata.check(e, self.extern_b_token, ctx())
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["evidence"]["metadata.symbol"], "xTOKB")
        self.assertEqual(f["evidence"]["metadata.icon_url"], "https://example-bridge-b.test/tokens/icons/token.png")

    def test_badge_manager_missing_name_is_informational_low(self):
        # Real: metadata.total_count is 0 on this component -- no name set at all.
        e = entity("guild-badge-manager", "Radix Guild", "guild", self.badge_manager["address"], "component", "Badge Manager")
        f = metadata.check(e, self.badge_manager, ctx())
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "low")
        self.assertIn("missing expected metadata field", f["reason"])

    def test_package_with_no_naming_convention_is_pass(self):
        # Real: an external package carries dapp_definition/registry/hook_packages but no name --
        # packages have no observed naming convention, so this is not penalized.
        e = entity("extern-a-package", "External A", "external", self.extern_a_pkg["address"], "package", "Package")
        f = metadata.check(e, self.extern_a_pkg, ctx())
        self.assertEqual(f["status"], "pass")

    def test_url_typed_field_present_as_wrong_type_is_informational_low(self):
        item = {"address": "resource_rdx1synthetic",
                "metadata": {"items": [{"key": "icon_url", "value": {"typed": {"value": "not-a-url-type", "type": "String"}}}]},
                "details": {}}
        e = entity("synthetic", "Synthetic", "external", "resource_rdx1synthetic", "resource", "Synthetic")
        f = metadata.check(e, item, ctx())
        self.assertEqual(f["status"], "informational")
        self.assertEqual(f["severity"], "low")
        self.assertIn("not 'Url'", f["reason"])


if __name__ == "__main__":
    unittest.main()
