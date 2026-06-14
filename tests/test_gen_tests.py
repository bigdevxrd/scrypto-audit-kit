"""Unit tests for bin/gen_tests.py — deterministic property-test scaffolding."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import gen_tests  # noqa: E402

PKG = os.path.join(ROOT, "examples", "vulnerable-vault")


class TestGenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = gen_tests.propose_tests(PKG)
        cls.names = {s["name"] for s in cls.result["specs"]}

    def test_blueprint_detected(self):
        self.assertEqual(self.result["blueprint"], "VulnerableVault")

    def test_count(self):
        self.assertEqual(self.result["count"], 8)

    def test_auth_negative_for_restricted_methods(self):
        for m in ("set_fee_bps", "pause", "unpause"):
            self.assertIn(f"{m}_rejects_unauthorized_caller", self.names)

    def test_happy_path_for_public_methods(self):
        for m in ("deposit", "withdraw", "set_oracle_price", "emergency_drain"):
            self.assertIn(f"{m}_happy_path", self.names)

    def test_value_invariant_present(self):
        self.assertIn("value_conservation_invariant", self.names)

    def test_surface_extraction(self):
        s = gen_tests.extract_surface(PKG)
        self.assertIn("admin", s["roles"])
        self.assertIn("vault", s["vault_fields"])
        gating = {m["name"]: m["gating"] for m in s["methods"]}
        self.assertEqual(gating["deposit"], "public")
        self.assertEqual(gating["set_fee_bps"], "restricted")

    def test_rust_well_formed(self):
        rust = self.result["rust"]
        self.assertEqual(rust.count("#[test]"), 8)
        self.assertEqual(rust.count('#[ignore = "scaffold'), 8)
        self.assertEqual(rust.count("fn "), 8)
        self.assertEqual(rust.count("{"), rust.count("}"))  # balanced braces
        self.assertIn("#![allow(unused)]", rust)
        self.assertIn("use scrypto_test::prelude::*;", rust)

    def test_empty_package_is_safe(self):
        # a dir with no .rs (the schema dir) — no surface, but still valid output
        res = gen_tests.propose_tests(os.path.join(ROOT, "schema"))
        self.assertEqual(res["count"], 0)
        self.assertIn("No role-restricted", res["rust"])


if __name__ == "__main__":
    unittest.main()
