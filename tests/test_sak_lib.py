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

    def test_merge_llm_suppresses_static_at_same_location(self):
        # a genuine duplicate: the LLM and static pass cite the same signature at the same line
        # — one entry (the LLM's), not two.
        primary = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86", "source": "llm"}]
        extra = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86", "source": "static"}]
        merged = sak_lib.merge_findings(primary, extra)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source"], "llm")

    def test_merge_llm_does_not_suppress_static_at_different_location(self):
        # BUG-HUNT-2026-07-18 M1: dedup against primary used to be location-INDEPENDENT (bare
        # signature only), so an LLM finding at one line silently swallowed a static finding
        # sharing its signature at a DIFFERENT line too — even a line or two apart. Now only a
        # same-location match counts as "the same issue"; different lines both survive.
        primary = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:87", "source": "llm"}]
        extra = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86", "source": "static"}]
        merged = sak_lib.merge_findings(primary, extra)
        self.assertEqual(len(merged), 2)
        self.assertEqual({f["location"] for f in merged}, {"src/lib.rs:86", "src/lib.rs:87"})

    def test_merge_llm_finding_does_not_swallow_distinct_static_at_other_line(self):
        # The exact M1 reproduction: static finds raw-decimal-arith at :86 AND :98; the LLM pass
        # reports one raw-arith finding at :86 sharing the signature. Only :86 is a true
        # duplicate — :98 is a genuinely distinct footgun and must survive the merge (the old
        # behavior dropped BOTH static entries, losing :98 entirely).
        primary = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86", "source": "llm"}]
        extra = [
            {"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86", "source": "static"},
            {"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:98", "source": "static"},
        ]
        merged = sak_lib.merge_findings(primary, extra)
        self.assertEqual(len(merged), 2)
        self.assertEqual({f["location"] for f in merged}, {"src/lib.rs:86", "src/lib.rs:98"})

    def test_merge_false_positive_primary_does_not_mask_open_extra(self):
        # BUG-HUNT-2026-07-18 M1 "status-blind" facet: the LLM marks its finding false_positive
        # at the same spot a static rule (deterministic, reproducible) still calls open. The
        # merge must not let a non-deterministic model opinion silently erase the open static
        # finding from a `status=open` view.
        primary = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86",
                    "source": "llm", "status": "false_positive"}]
        extra = [{"class": "X", "title": "t", "severity": "medium", "location": "src/lib.rs:86",
                  "source": "static", "status": "open"}]
        merged = sak_lib.merge_findings(primary, extra)
        self.assertEqual(len(merged), 2)
        open_sources = {f["source"] for f in merged if f.get("status", "open") == "open"}
        self.assertEqual(open_sources, {"static"})

    def test_full_merge_keeps_all_fixture_findings(self):
        # oracle: a full/merged run over the planted-bug fixture must surface all 5 static findings,
        # not 4 — the two `raw arithmetic` findings (src/lib.rs:86 and :98) must not collapse.
        static = static_analysis.analyze_package(PKG)
        self.assertEqual(len(static), 7)  # +2: public-privileged-method on the fixture
        merged = sak_lib.merge_findings([], static)  # empty LLM appendix — pure static-into-hybrid merge
        self.assertEqual(len(merged), 7)  # +2: public-privileged-method on the fixture
        locs = {f["location"] for f in merged if f["rule"] == "raw-decimal-arith"}
        self.assertEqual(locs, {"src/lib.rs:86", "src/lib.rs:98"})

    def test_full_merge_with_llm_primary_keeps_distinct_static_raw_arith(self):
        # M2: the fixture-oracle test above calls merge_findings([], static) — an EMPTY LLM
        # primary — which can't exercise M1's bug (the drop only triggers when primary is
        # non-empty and shares a static finding's signature). Reproduce the production shape
        # against the real fixture: a non-empty LLM primary sharing its signature with the
        # src/lib.rs:86 raw-arith finding must not also take out the distinct one at :98.
        static = static_analysis.analyze_package(PKG)
        raw_arith_86 = next(f for f in static
                             if f["rule"] == "raw-decimal-arith" and f["location"] == "src/lib.rs:86")
        llm_primary = [{
            "class": raw_arith_86["class"], "title": raw_arith_86["title"],
            "severity": raw_arith_86["severity"], "location": "src/lib.rs:86", "source": "llm",
        }]
        merged = sak_lib.merge_findings(llm_primary, static)
        sig = sak_lib.finding_signature(raw_arith_86)
        locs = {f["location"] for f in merged if sak_lib.finding_signature(f) == sig}
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


class TestNewestReport(unittest.TestCase):
    """`newest_report` is advertised in docs/sdk.md but had no test and no in-tree caller.

    It is kept rather than removed: it is public API on a package that is already published, so
    deleting it breaks a downstream importer silently for no gain. Covered here instead, with the
    reason it must not be used as a gate fallback — picking "the newest report lying around" would
    let a stale clean report satisfy a gate for code that was never scanned.
    """

    def test_returns_the_most_recently_modified_json(self):
        d = tempfile.mkdtemp()
        old = os.path.join(d, "old.json")
        new = os.path.join(d, "new.json")
        for p in (old, new):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("{}")
        os.utime(old, (1_000_000, 1_000_000))
        os.utime(new, (2_000_000, 2_000_000))
        self.assertEqual(sak_lib.newest_report(d), new)

    def test_returns_none_on_an_empty_directory(self):
        self.assertIsNone(sak_lib.newest_report(tempfile.mkdtemp()))

    def test_returns_none_on_a_missing_directory(self):
        self.assertIsNone(sak_lib.newest_report(os.path.join(tempfile.mkdtemp(), "nope")))
