"""Unit tests for scanner/cohort.py -- validation is strict and fails closed, since a malformed
cohort entry could otherwise silently drop an entity from a public transparency page.
"""
import copy
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanner import cohort  # noqa: E402

REAL_COHORT_PATH = os.path.join(ROOT, "scanner", "data", "cohort.json")

VALID_ENTITY = {
    "id": "example-entity",
    "project": "Example",
    "category": "external",
    "address": "component_rdx1cpmgqg4cuq54a74kl38g03wfxjsq9w02e8twt79jlh0sw4qpnrylpj",
    "entity_kind": "component",
    "label": "Example component",
}


def _write(tmpdir, data):
    path = os.path.join(tmpdir, "cohort.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


class TestRealCohortFile(unittest.TestCase):
    """The actual cohort.json shipped in this repository must itself pass validation.

    This is the PUBLIC, committed cohort -- only the Guild's own entities, deliberately: a
    third party named here as a scan target, while the publication gate withholds its results,
    would insinuate a problem with no evidence behind it. A local, gitignored
    scanner/data/cohort-full.json can add external projects for an operator's own runs; see
    scanner/cli.py's DEFAULT_FULL_COHORT_PATH and tests/test_scanner_report.py's own inline
    full-cohort fixture for the shape that exercises those code paths.
    """

    def test_real_cohort_loads_and_has_five_entities(self):
        entities = cohort.load_cohort(REAL_COHORT_PATH)
        self.assertEqual(len(entities), 5)
        ids = {e["id"] for e in entities}
        self.assertIn("guild-escrow-wave-b", ids)
        self.assertIn("guild-dapp-definition-2", ids)

    def test_real_cohort_is_guild_only(self):
        entities = cohort.load_cohort(REAL_COHORT_PATH)
        categories = {e["category"] for e in entities}
        self.assertEqual(categories, {"guild"})
        projects = {e["project"] for e in entities}
        self.assertEqual(projects, {"Radix Guild"})

    def test_real_cohort_has_one_dapp_definition_hub(self):
        entities = cohort.load_cohort(REAL_COHORT_PATH)
        hubs = [e for e in entities if e.get("role") == "dapp_definition_hub"]
        self.assertEqual(len(hubs), 1)
        self.assertEqual(hubs[0]["project"], "Radix Guild")


class TestValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_valid_single_entity_cohort_loads(self):
        path = _write(self.tmp.name, {"entities": [VALID_ENTITY]})
        entities = cohort.load_cohort(path)
        self.assertEqual(entities, [VALID_ENTITY])

    def test_missing_file_raises(self):
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(os.path.join(self.tmp.name, "nope.json"))

    def test_not_json_raises(self):
        path = os.path.join(self.tmp.name, "bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_missing_entities_key_raises(self):
        path = _write(self.tmp.name, {"notes": []})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_empty_entities_raises(self):
        path = _write(self.tmp.name, {"entities": []})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_missing_required_field_raises(self):
        bad = copy.deepcopy(VALID_ENTITY)
        del bad["label"]
        path = _write(self.tmp.name, {"entities": [bad]})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_bad_category_raises(self):
        bad = {**VALID_ENTITY, "category": "friendly"}
        path = _write(self.tmp.name, {"entities": [bad]})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_bad_entity_kind_raises(self):
        bad = {**VALID_ENTITY, "entity_kind": "wallet"}
        path = _write(self.tmp.name, {"entities": [bad]})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_address_kind_mismatch_raises(self):
        # address is a component_ but entity_kind claims resource -- must be rejected, not
        # silently trusted, since a check would then read the wrong role-key vocabulary.
        bad = {**VALID_ENTITY, "entity_kind": "resource"}
        path = _write(self.tmp.name, {"entities": [bad]})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_malformed_address_raises(self):
        bad = {**VALID_ENTITY, "address": "not-a-radix-address"}
        path = _write(self.tmp.name, {"entities": [bad]})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_bad_id_format_raises(self):
        bad = {**VALID_ENTITY, "id": "Not Valid ID!"}
        path = _write(self.tmp.name, {"entities": [bad]})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_duplicate_id_raises(self):
        other = {**VALID_ENTITY, "address": "resource_rdx1t5deegdjgx93jtmm5vlf6xw84n4ppzkcq2r2c768zpkl2v3x8yry0s",
                 "entity_kind": "resource"}
        path = _write(self.tmp.name, {"entities": [VALID_ENTITY, other]})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)

    def test_duplicate_address_raises(self):
        other = {**VALID_ENTITY, "id": "example-entity-two"}
        path = _write(self.tmp.name, {"entities": [VALID_ENTITY, other]})
        with self.assertRaises(cohort.CohortError):
            cohort.load_cohort(path)


if __name__ == "__main__":
    unittest.main()
