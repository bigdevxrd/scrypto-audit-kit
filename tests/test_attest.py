"""Unit tests for bin/attest.py — the report -> attestation bridge."""
import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import attest  # noqa: E402

SAMPLE = os.path.join(ROOT, "examples", "vulnerable-vault.pre-audit.json")


class TestAttest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = attest.build_payload(SAMPLE)

    def test_counts(self):
        p = self.payload
        self.assertEqual((p["critical"], p["high"], p["medium"], p["low"], p["info"]), (2, 2, 3, 1, 0))

    def test_source_hash_from_report(self):
        report = json.load(open(SAMPLE, encoding="utf-8"))
        self.assertEqual(self.payload["source_hash"], report["target"]["source_hash"])

    def test_report_hash_is_sha256_of_file(self):
        expected = hashlib.sha256(open(SAMPLE, "rb").read()).hexdigest()
        self.assertEqual(self.payload["report_hash"], expected)
        self.assertEqual(len(self.payload["report_hash"]), 64)

    def test_level_hybrid(self):
        self.assertEqual(self.payload["level"], "L2-hybrid")

    def test_level_override(self):
        self.assertEqual(attest.build_payload(SAMPLE, level="L3-attested")["level"], "L3-attested")

    def test_wasm_hash_empty_without_wasm(self):
        self.assertEqual(self.payload["wasm_hash"], "")

    def test_provenance_from_report(self):
        self.assertEqual(self.payload["kit_version"], "0.1.0")
        self.assertEqual(self.payload["checklist_version"], "1.0")

    def test_manifest_shape(self):
        m = attest.render_manifest(self.payload, "component_rdx1abc", "account_rdx1xyz")
        self.assertIn("CALL_METHOD", m)
        self.assertIn('"attest"', m)
        self.assertIn("Tuple(", m)
        self.assertIn("component_rdx1abc", m)
        self.assertIn("account_rdx1xyz", m)
        self.assertIn('Expression("ENTIRE_WORKTOP")', m)
        self.assertEqual(m.count("u16"), 5)        # 5 severity counts
        self.assertIn("2u16", m)                   # critical
        self.assertIn('"L2-hybrid"', m)


if __name__ == "__main__":
    unittest.main()
