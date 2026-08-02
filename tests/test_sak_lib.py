"""Unit tests for bin/sak_lib.py, exercised against the committed sample report."""
import copy
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import sak_lib  # noqa: E402
import static_analysis  # noqa: E402

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

    def test_merge_keeps_distinct_severities(self):
        # an info finding must not collide with / hide a critical sharing class+title
        primary = [{"class": "X", "title": "t", "severity": "info"}]
        extra = [{"class": "X", "title": "t", "severity": "critical"}]
        merged = sak_lib.merge_findings(primary, extra)
        self.assertEqual(sorted(f["severity"] for f in merged), ["critical", "info"])

    def test_merge_dedups_true_duplicates(self):
        a = [{"class": "X", "title": "t", "severity": "high"}]
        b = [{"class": "X", "title": "t", "severity": "high"}]
        self.assertEqual(len(sak_lib.merge_findings(a, b)), 1)

    def test_merge_keeps_distinct_static_locations(self):
        # two static findings share a signature but sit at different lines — both are real footguns
        # and must survive the merge (regression: the bare-signature dedup collapsed them into one).
        extra = [
            {"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86"},
            {"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:98"},
        ]
        merged = sak_lib.merge_findings([], extra)
        self.assertEqual(sorted(f["location"] for f in merged), ["src/lib.rs:86", "src/lib.rs:98"])

    def test_merge_dedups_same_signature_same_location(self):
        # a genuine duplicate — same signature AND same location — still collapses to one.
        extra = [
            {"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86"},
            {"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86"},
        ]
        self.assertEqual(len(sak_lib.merge_findings([], extra)), 1)

    def test_merge_llm_suppresses_static_regardless_of_line(self):
        # the LLM's location-independent dedup is preserved: an LLM finding suppresses a static one
        # that shares its signature even when the cited line differs by a line or two.
        primary = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:87", "source": "llm"}]
        extra = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86", "source": "static"}]
        merged = sak_lib.merge_findings(primary, extra)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source"], "llm")

    def test_full_merge_keeps_all_fixture_findings(self):
        # oracle: a full/merged run over the planted-bug fixture must surface all 5 static findings,
        # not 4 — the two `raw arithmetic` findings (src/lib.rs:86 and :98) must not collapse.
        static = static_analysis.analyze_package(PKG)
        self.assertEqual(len(static), 5)
        merged = sak_lib.merge_findings([], static)  # empty LLM appendix — pure static-into-hybrid merge
        self.assertEqual(len(merged), 5)
        locs = {f["location"] for f in merged if f["rule"] == "raw-decimal-arith"}
        self.assertEqual(locs, {"src/lib.rs:86", "src/lib.rs:98"})

    def test_read_source_span_marks_cited_line(self):
        span = sak_lib.read_source_span(PKG, "src/lib.rs:87", context=2)
        self.assertEqual(span["line"], 87)
        self.assertIn("87>", span["snippet"])      # cited line is marked
        self.assertIn("shares", span["snippet"])

    def test_read_source_span_missing_file(self):
        self.assertIn("error", sak_lib.read_source_span(PKG, "src/nope.rs:1"))

    def test_read_source_span_no_line(self):
        self.assertIn("error", sak_lib.read_source_span(PKG, "src/lib.rs"))

    def test_read_source_span_absolute_path_confined(self):
        # An absolute location must not read outside the package (path-traversal / exfil).
        span = sak_lib.read_source_span(PKG, "/etc/passwd:1")
        self.assertIn("error", span)
        self.assertNotIn("snippet", span)

    def test_read_source_span_dotdot_confined(self):
        span = sak_lib.read_source_span(PKG, "../../../../../../etc/passwd:1")
        self.assertIn("error", span)
        self.assertNotIn("snippet", span)

    def test_collect_findings_valid_returns_list(self):
        self.assertEqual(len(sak_lib.collect_findings(SAMPLE)), 8)

    def test_collect_findings_missing_raises(self):
        with self.assertRaises(sak_lib.GateError):
            sak_lib.collect_findings(os.path.join(tempfile.mkdtemp(), "nope.json"))

    def test_collect_findings_allow_missing_returns_none(self):
        self.assertIsNone(
            sak_lib.collect_findings(os.path.join(tempfile.mkdtemp(), "nope.json"), allow_missing=True))

    def test_collect_findings_malformed_raises(self):
        p = os.path.join(tempfile.mkdtemp(), "r.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        with self.assertRaises(sak_lib.GateError):
            sak_lib.collect_findings(p)

    def test_collect_findings_no_array_raises(self):
        p = os.path.join(tempfile.mkdtemp(), "r.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("{}")
        with self.assertRaises(sak_lib.GateError):
            sak_lib.collect_findings(p)


if __name__ == "__main__":
    unittest.main()
