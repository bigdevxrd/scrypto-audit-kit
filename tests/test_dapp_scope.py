"""Unit tests for bin/dapp_scope.py — dapp-scope questionnaire validation + report rendering.

Three things this covers, per the first slice's design (docs/DAPP-SCOPE-EXTENSION.md §5):
  1. Validation — both the jsonschema-backed path and the stdlib-only structural fallback agree.
  2. Rendering — markdown + the embedded JSON appendix, including the not-applicable path.
  3. The unbounded-is-a-finding rule (§3) — an unbounded max_loss becomes a U-### finding and
     nothing else does.
"""
import builtins
import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import dapp_scope  # noqa: E402

EXAMPLE_PATH = os.path.join(ROOT, "examples", "dapp-scope", "questionnaire.example.json")
SCHEMA_PATH = os.path.join(ROOT, "schema", "dapp-scope-questionnaire.schema.json")


def _load_example():
    with open(EXAMPLE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _without_jsonschema(fn):
    """Run fn() with `import jsonschema` forced to fail, to exercise the structural fallback."""
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = blocked
    try:
        return fn()
    finally:
        builtins.__import__ = real_import


class TestSchemaAndExampleFilesExist(unittest.TestCase):
    def test_schema_file_is_valid_json(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        self.assertEqual(schema["$id"].rstrip("/"),
                          "https://github.com/bigdevxrd/scrypto-audit-kit/blob/main/schema/dapp-scope-questionnaire.schema.json")

    def test_default_schema_path_resolves_to_repo_schema(self):
        self.assertEqual(os.path.abspath(dapp_scope.DEFAULT_SCHEMA_PATH), os.path.abspath(SCHEMA_PATH))

    def test_example_questionnaire_is_valid(self):
        self.assertEqual(dapp_scope.validate_questionnaire(_load_example()), [])


class TestValidationBothBackends(unittest.TestCase):
    """Every case here is asserted against BOTH the jsonschema path (available in this test env)
    and the stdlib structural fallback, so the two never silently drift apart."""

    def _check(self, data, expect_valid):
        with_js = dapp_scope.validate_questionnaire(data)
        without_js = _without_jsonschema(lambda: dapp_scope.validate_questionnaire(data))
        if expect_valid:
            self.assertEqual(with_js, [], f"jsonschema path: {with_js}")
            self.assertEqual(without_js, [], f"fallback path: {without_js}")
        else:
            self.assertTrue(with_js, "jsonschema path found no errors, expected some")
            self.assertTrue(without_js, "fallback path found no errors, expected some")

    def test_valid_example_passes_both(self):
        self._check(_load_example(), expect_valid=True)

    def test_missing_top_level_field(self):
        data = _load_example()
        del data["dapp_name"]
        self._check(data, expect_valid=False)

    def test_bad_schema_version(self):
        data = _load_example()
        data["schema_version"] = "2.0"
        self._check(data, expect_valid=False)

    def test_bad_answered_at_format(self):
        data = _load_example()
        data["answered_at"] = "09/04/2026"
        self._check(data, expect_valid=False)

    def test_not_applicable_without_justification(self):
        data = _load_example()
        data["listings"] = {"applicable": False}
        self._check(data, expect_valid=False)

    def test_not_applicable_with_justification_is_valid(self):
        data = _load_example()
        data["listings"] = {"applicable": False, "justification": "single fixed-asset vault, no listing process"}
        self._check(data, expect_valid=True)

    def test_applicable_true_requires_items(self):
        data = _load_example()
        data["listings"] = {"applicable": True}
        self._check(data, expect_valid=False)

    def test_applicable_true_with_empty_items_is_invalid(self):
        data = _load_example()
        data["listings"] = {"applicable": True, "items": []}
        self._check(data, expect_valid=False)

    def test_item_missing_required_field(self):
        data = _load_example()
        del data["data_sources"]["items"][0]["trust_model"]
        self._check(data, expect_valid=False)

    def test_bad_trust_model_enum(self):
        data = _load_example()
        data["data_sources"]["items"][0]["trust_model"] = "vibes"
        self._check(data, expect_valid=False)

    def test_bad_holder_enum(self):
        data = _load_example()
        data["admin_powers"]["items"][0]["holder"] = "a_guy_with_a_laptop"
        self._check(data, expect_valid=False)

    def test_max_loss_missing_rationale(self):
        data = _load_example()
        del data["data_sources"]["items"][0]["max_loss"]["rationale"]
        self._check(data, expect_valid=False)

    def test_max_loss_bounded_true_requires_bound_description(self):
        data = _load_example()
        data["data_sources"]["items"][1]["max_loss"] = {"bounded": True, "rationale": "no cap given"}
        self._check(data, expect_valid=False)

    def test_max_loss_bounded_false_needs_no_bound_description(self):
        data = _load_example()
        data["data_sources"]["items"][0]["max_loss"] = {"bounded": False, "rationale": "unbounded, no cap"}
        self._check(data, expect_valid=True)

    def test_single_signature_requires_accepted_risk_justification(self):
        data = _load_example()
        data["admin_powers"]["items"][0]["single_signature_sufficient"] = True
        del data["admin_powers"]["items"][0]["accepted_risk_justification"]
        self._check(data, expect_valid=False)

    def test_single_signature_false_needs_no_justification(self):
        data = _load_example()
        item = data["admin_powers"]["items"][0]
        item["single_signature_sufficient"] = False
        del item["accepted_risk_justification"]
        self._check(data, expect_valid=True)

    def test_operational_response_missing_fastest_lever(self):
        data = _load_example()
        del data["operational_response"]["fastest_lever"]
        self._check(data, expect_valid=False)

    def test_operational_response_bad_fastest_lever_enum(self):
        data = _load_example()
        data["operational_response"]["fastest_lever"] = "vibes"
        self._check(data, expect_valid=False)

    def test_operational_response_not_applicable_is_valid(self):
        data = _load_example()
        data["operational_response"] = {"applicable": False, "justification": "no live deployment yet"}
        self._check(data, expect_valid=True)

    def test_root_must_be_object(self):
        with_js = dapp_scope.validate_questionnaire([1, 2, 3])
        without_js = _without_jsonschema(lambda: dapp_scope.validate_questionnaire([1, 2, 3]))
        self.assertTrue(with_js)
        self.assertTrue(without_js)


class TestUnboundedIsAFinding(unittest.TestCase):
    def test_example_has_exactly_the_two_unbounded_items(self):
        data = _load_example()
        findings = dapp_scope.find_unbounded_findings(data)
        ids = {f["id"] for f in findings}
        self.assertEqual(ids, {"U-001", "U-002"})
        surfaces_and_items = {(f["surface"], f["item"]) for f in findings}
        self.assertIn(("data_sources", "XRD/USD price feed (single relayer)"), surfaces_and_items)
        self.assertIn(("admin_powers", "rotate owner badge"), surfaces_and_items)

    def test_bounded_item_is_never_a_finding(self):
        data = _load_example()
        findings = dapp_scope.find_unbounded_findings(data)
        items = {f["item"] for f in findings}
        self.assertNotIn("component TVL read (own state)", items)
        self.assertNotIn("xUSDC collateral", items)
        self.assertNotIn("pause new borrows", items)

    def test_all_bounded_yields_no_findings(self):
        data = _load_example()
        data["data_sources"]["items"][0]["max_loss"] = {
            "bounded": True, "bound_description": "capped by vault balance", "rationale": "now bounded",
        }
        data["admin_powers"]["items"][1]["max_loss"] = {
            "bounded": True, "bound_description": "timelocked now", "rationale": "now bounded",
        }
        self.assertEqual(dapp_scope.find_unbounded_findings(data), [])

    def test_not_applicable_surface_contributes_no_findings(self):
        data = _load_example()
        data["admin_powers"] = {"applicable": False, "justification": "immutable, no admin badge exists"}
        findings = dapp_scope.find_unbounded_findings(data)
        self.assertNotIn("admin_powers", {f["surface"] for f in findings})
        # the still-applicable data_sources unbounded item remains
        self.assertIn("U-001", {f["id"] for f in findings})

    def test_operational_response_never_produces_a_finding(self):
        # operational_response has no max_loss field at all — it cannot appear in find_unbounded_findings.
        data = _load_example()
        findings = dapp_scope.find_unbounded_findings(data)
        self.assertNotIn("operational_response", {f["surface"] for f in findings})

    def test_finding_ids_are_sequential(self):
        data = _load_example()
        findings = dapp_scope.find_unbounded_findings(data)
        self.assertEqual([f["id"] for f in findings], ["U-001", "U-002"])


class TestReportAndRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load_example()
        cls.report = dapp_scope.build_report(cls.data, generated_at="2026-09-04T00:00:00Z")
        cls.md = dapp_scope.render_markdown(cls.report)

    def test_report_is_its_own_schema_axis(self):
        # never confusable with schema/audit-report.schema.json output
        self.assertEqual(self.report["report_type"], "dapp-scope")
        self.assertFalse(self.report["attested"])

    def test_report_has_no_source_hash(self):
        self.assertNotIn("source_hash", self.report)
        self.assertNotIn("source_hash", json.dumps(self.report))

    def test_report_carries_freshness_marker(self):
        self.assertEqual(self.report["answered_at"], "2026-09-04")

    def test_report_unbounded_findings_match_helper(self):
        self.assertEqual(self.report["unbounded_findings"], dapp_scope.find_unbounded_findings(self.data))

    def test_markdown_has_freshness_language(self):
        self.assertIn("organizational facts go stale", self.md)
        self.assertIn("2026-09-04", self.md)

    def test_markdown_states_not_an_attestation(self):
        self.assertIn("Not an attestation", self.md)
        self.assertIn("L1", self.md)  # references the attestation ladder by name

    def test_markdown_lists_unbounded_findings(self):
        self.assertIn("U-001", self.md)
        self.assertIn("U-002", self.md)
        self.assertIn("**unbounded**", self.md)

    def test_markdown_all_four_surfaces_present(self):
        for heading in ("2.1 Data sources", "2.2 Listing / registry configuration",
                        "2.3 Admin powers", "2.4 Operational response"):
            self.assertIn(heading, self.md)

    def test_markdown_embeds_valid_json_appendix(self):
        marker = "<!-- machine-readable: do not edit -->\n```json\n"
        idx = self.md.index(marker) + len(marker)
        end = self.md.index("\n```", idx)
        embedded = json.loads(self.md[idx:end])
        self.assertEqual(embedded, self.report)

    def test_render_no_findings_says_so(self):
        data = copy.deepcopy(self.data)
        data["data_sources"]["items"][0]["max_loss"] = {
            "bounded": True, "bound_description": "capped", "rationale": "now bounded",
        }
        data["admin_powers"]["items"][1]["max_loss"] = {
            "bounded": True, "bound_description": "timelocked", "rationale": "now bounded",
        }
        report = dapp_scope.build_report(data)
        md = dapp_scope.render_markdown(report)
        self.assertIn("No unbounded-loss findings", md)

    def test_render_not_applicable_surface(self):
        data = copy.deepcopy(self.data)
        data["listings"] = {"applicable": False, "justification": "single fixed-asset vault"}
        report = dapp_scope.build_report(data)
        md = dapp_scope.render_markdown(report)
        self.assertIn("**Not applicable** — single fixed-asset vault", md)


class TestRunEndToEnd(unittest.TestCase):
    def test_run_on_example_file(self):
        report = dapp_scope.run(EXAMPLE_PATH)
        self.assertEqual(report["report_type"], "dapp-scope")
        self.assertEqual(len(report["unbounded_findings"]), 2)

    def test_run_raises_on_invalid_questionnaire(self, tmp_name="_tmp_invalid_questionnaire.json"):
        path = os.path.join(HERE, tmp_name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": "1.0"}, fh)
        try:
            with self.assertRaises(dapp_scope.DappScopeError):
                dapp_scope.run(path)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
