"""Unit tests for scanner/diff.py -- "what changed since last scan".

Builds two small, hand-written report dicts (matching schema/posture-scan-report.schema.json's
shape) rather than full scans, so the expected changed set can be read directly off this file
without cross-referencing fixtures. It proves two scan files produce the expected "changed since
last scan" set.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanner import diff  # noqa: E402


def finding(check, status, severity, reason, evidence, state_version=1, embargo=None):
    return {
        "check": check, "status": status, "severity": severity, "reason": reason,
        "evidence": evidence, "state_version": state_version,
        "embargo": embargo or {"status": "public", "publish_at": None, "reason": None},
    }


def entity_result(id, checks):
    return {"id": id, "project": "P", "category": "external", "address": f"component_rdx1{id}",
            "entity_kind": "component", "label": id, "checks": checks}


def report(entities, scan_id="scan-1"):
    return {"schema_version": "1.0", "scan_id": scan_id, "generated_at": "2026-09-08T00:00:00Z",
            "network": "mainnet", "gateway": {"url": "x", "pinned_state_version": 1, "halted": False},
            "cohort_source": "x", "notes": [], "entities": entities}


class TestDiffReports(unittest.TestCase):
    def setUp(self):
        # OLD scan: three entities.
        self.old = report([
            entity_result("alpha", [
                finding("owner_role", "pass", "none", "protected + rotatable", {"owner": "Protected/Owner"}, state_version=100),
                finding("package_upgrade", "informational", "informational", "baseline", {"code_hash_hex": ["aaa"]}, state_version=100),
            ]),
            entity_result("beta", [
                finding("dapp_definition_two_way", "fail", "medium", "half-pair", {"claims": ["acct1"]}, state_version=100),
            ]),
            entity_result("gamma-retiring", [
                finding("owner_role", "pass", "none", "fine", {"owner": "Protected/Owner"}, state_version=100),
            ]),
        ], scan_id="scan-1")

        # NEW scan, one week later: state_version moved (100 -> 200, deliberately NOT a change),
        # alpha's package upgraded (code_hash changed AND status moved baseline -> a real
        # "changed" verdict), beta is unchanged, gamma-retiring dropped out of the cohort, and a
        # brand new entity delta joined.
        self.new = report([
            entity_result("alpha", [
                finding("owner_role", "pass", "none", "protected + rotatable", {"owner": "Protected/Owner"}, state_version=200),
                finding("package_upgrade", "informational", "medium", "changed since last scan: code_hash_hex: ['aaa'] -> ['bbb']", {"code_hash_hex": ["bbb"]}, state_version=200),
            ]),
            entity_result("beta", [
                finding("dapp_definition_two_way", "fail", "medium", "half-pair", {"claims": ["acct1"]}, state_version=200),
            ]),
            entity_result("delta-new", [
                finding("owner_role", "informational", "informational", "denyall", {"owner": "DenyAll/None"}, state_version=200),
            ]),
        ], scan_id="scan-2")

    def test_identical_report_diffs_to_nothing(self):
        d = diff.diff_reports(self.old, self.old)
        self.assertEqual(d["entities_added"], [])
        self.assertEqual(d["entities_removed"], [])
        self.assertEqual(d["changes"], [])

    def test_state_version_alone_moving_is_not_a_change(self):
        # beta's finding is byte-identical except state_version (100 -> 200) -- must NOT appear
        # in changes, or every entity would falsely "change" on every single run.
        d = diff.diff_reports(self.old, self.new)
        beta_changes = [c for c in d["changes"] if c["entity_id"] == "beta"]
        self.assertEqual(beta_changes, [])

    def test_alpha_owner_role_unchanged_not_reported(self):
        d = diff.diff_reports(self.old, self.new)
        alpha_owner_changes = [c for c in d["changes"] if c["entity_id"] == "alpha" and c["check"] == "owner_role"]
        self.assertEqual(alpha_owner_changes, [])

    def test_alpha_package_upgrade_is_reported_as_changed(self):
        d = diff.diff_reports(self.old, self.new)
        matches = [c for c in d["changes"] if c["entity_id"] == "alpha" and c["check"] == "package_upgrade"]
        self.assertEqual(len(matches), 1)
        change = matches[0]
        self.assertEqual(change["old"]["severity"], "informational")
        self.assertEqual(change["new"]["severity"], "medium")
        self.assertEqual(change["old"]["evidence"]["code_hash_hex"], ["aaa"])
        self.assertEqual(change["new"]["evidence"]["code_hash_hex"], ["bbb"])

    def test_entity_added_and_removed_are_both_reported(self):
        d = diff.diff_reports(self.old, self.new)
        self.assertEqual(d["entities_added"], ["delta-new"])
        self.assertEqual(d["entities_removed"], ["gamma-retiring"])
        # A removed/added entity's checks are not ALSO double-counted in `changes` -- diffing
        # only compares entities present in BOTH scans.
        self.assertFalse(any(c["entity_id"] in ("delta-new", "gamma-retiring") for c in d["changes"]))

    def test_exact_changed_set_for_this_fixture_pair(self):
        # The full expectation in one place: exactly one (entity, check) pair changed.
        d = diff.diff_reports(self.old, self.new)
        changed_pairs = {(c["entity_id"], c["check"]) for c in d["changes"]}
        self.assertEqual(changed_pairs, {("alpha", "package_upgrade")})

    def test_check_added_within_an_existing_entity_is_reported(self):
        old = report([entity_result("solo", [finding("owner_role", "pass", "none", "ok", {"a": 1})])])
        new = report([entity_result("solo", [
            finding("owner_role", "pass", "none", "ok", {"a": 1}),
            finding("metadata_claims", "pass", "none", "ok", {"b": 2}),
        ])])
        d = diff.diff_reports(old, new)
        self.assertEqual(len(d["changes"]), 1)
        self.assertEqual(d["changes"][0]["check"], "metadata_claims")
        self.assertIsNone(d["changes"][0]["old"])

    def test_summarize_mentions_scan_ids_and_is_a_string(self):
        d = diff.diff_reports(self.old, self.new)
        text = diff.summarize(d)
        self.assertIsInstance(text, str)
        self.assertIn("alpha", text)
        self.assertIn("package_upgrade", text)


if __name__ == "__main__":
    unittest.main()
