"""Unit tests for bin/sak_lib.py, exercised against the committed sample report."""
import copy
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import sak_lib  # noqa: E402

SAMPLE = os.path.join(ROOT, "examples", "vulnerable-vault.pre-audit.json")
PKG = os.path.join(ROOT, "examples", "vulnerable-vault")


class TestSakLib(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = sak_lib.load_report(SAMPLE)

    def test_load_report(self):
        self.assertEqual(self.report["schema_version"], "1.0")
        self.assertEqual(len(self.report["findings"]), 8)

    def test_filter_severity_min(self):
        self.assertEqual(len(sak_lib.filter_findings(self.report, severity_min="critical")), 2)
        self.assertEqual(len(sak_lib.filter_findings(self.report, severity_min="high")), 4)
        self.assertEqual(len(sak_lib.filter_findings(self.report, severity_min="info")), 8)

    def test_filter_status(self):
        self.assertEqual(len(sak_lib.filter_findings(self.report, status="open")), 8)
        self.assertEqual(sak_lib.filter_findings(self.report, status="fixed"), [])

    def test_severity_counts(self):
        counts = sak_lib.severity_counts(self.report["findings"])
        self.assertEqual((counts.get("critical"), counts.get("high"), counts.get("medium"), counts.get("low")),
                         (2, 2, 3, 1))

    def test_counts_summary(self):
        self.assertEqual(sak_lib.counts_summary({"high": 2, "low": 1}), "high:2, low:1")
        self.assertEqual(sak_lib.counts_summary({}), "none")

    def test_gate_high_fails(self):
        verdict = sak_lib.gate_verdict(self.report, "high")
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["worst"], "critical")
        self.assertEqual(verdict["total"], 8)

    def test_gate_none_passes(self):
        self.assertTrue(sak_lib.gate_verdict(self.report, "none")["passed"])

    def test_gate_bad_threshold_raises(self):
        with self.assertRaises(ValueError):
            sak_lib.gate_verdict(self.report, "bogus")

    def test_diff_detects_fixed_still_and_new(self):
        current = copy.deepcopy(self.report)
        current["findings"] = [f for f in current["findings"] if f["id"] != "F-001"]
        current["findings"].append({
            "id": "F-099", "severity": "low", "class": "Event emission",
            "title": "a brand new issue", "location": "src/lib.rs:1",
            "what": "x", "why": "y", "suggested_direction": "z", "confidence": "low",
        })
        diff = sak_lib.diff_reports(self.report, current)
        self.assertTrue(any(f["id"] == "F-001" for f in diff["fixed"]))
        self.assertTrue(any(f["id"] == "F-099" for f in diff["new"]))
        self.assertEqual(len(diff["still_open"]), 7)

    def test_read_source_span_marks_cited_line(self):
        span = sak_lib.read_source_span(PKG, "src/lib.rs:87", context=2)
        self.assertEqual(span["line"], 87)
        self.assertIn("87>", span["snippet"])      # cited line is marked
        self.assertIn("shares", span["snippet"])

    def test_read_source_span_missing_file(self):
        self.assertIn("error", sak_lib.read_source_span(PKG, "src/nope.rs:1"))

    def test_read_source_span_no_line(self):
        self.assertIn("error", sak_lib.read_source_span(PKG, "src/lib.rs"))


if __name__ == "__main__":
    unittest.main()
