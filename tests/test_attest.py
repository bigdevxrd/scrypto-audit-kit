"""Unit tests for bin/attest.py — the report -> attestation bridge."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import attest  # noqa: E402
import sak_lib  # noqa: E402

SAMPLE = os.path.join(ROOT, "examples", "vulnerable-vault.pre-audit.json")


class TestAttest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = attest.build_payload(SAMPLE)

    def test_counts(self):
        p = self.payload
        self.assertEqual((p["critical"], p["high"], p["medium"], p["low"], p["info"]), (2, 2, 3, 1, 0))

    def test_source_hash_from_report(self):
        with open(SAMPLE, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(self.payload["source_hash"], report["target"]["source_hash"])

    def test_report_hash_is_sha256_of_file(self):
        with open(SAMPLE, "rb") as fh:
            expected = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(self.payload["report_hash"], expected)
        self.assertEqual(len(self.payload["report_hash"]), 64)

    def test_mode_reflects_the_tiers_that_ran(self):
        # The sample predates the static tier — it is an LLM-only run and must say so.
        self.assertEqual(self.payload["mode"], "llm")

    def test_no_level_field_is_emitted(self):
        """A trust level must never be a payload field — it is the reader's to compute.

        This replaces a test that asserted an arbitrary caller-supplied level (\"L3-attested\")
        passed through untouched. That was a regression test FOR the forgery path: L3 is
        conferred by the on-chain record existing, so it can never be an input to it.
        """
        self.assertNotIn("level", self.payload)
        self.assertNotIn("level", attest._STR_FIELDS)

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
        self.assertIn('"llm"', m)

    def test_derive_mode_reads_tiers_not_the_model_string(self):
        d = attest._derive_mode
        self.assertEqual(d({"kit": {"tiers": ["static"]}}), "static")
        self.assertEqual(d({"kit": {"tiers": ["llm"]}}), "llm")
        self.assertEqual(d({"kit": {"tiers": ["static", "llm"]}}), "hybrid")
        # a clean full run (0 findings) is still hybrid — the tiers ran, they just found nothing
        self.assertEqual(d({"kit": {"tiers": ["static", "llm"]}, "findings": []}), "hybrid")

    def test_derive_mode_fails_low_on_absent_or_junk_tiers(self):
        """Climbing requires positive evidence. The old code parsed kit.model and returned the
        HIGHER claim on anything it did not recognise, so an unknown or user-supplied model
        string asserted that the LLM checklist pass had run."""
        d = attest._derive_mode
        for report in ({"kit": {}},                                     # pre-0.8.0 report
                       {"kit": {"tiers": []}},                          # nothing ran
                       {"kit": {"tiers": "llm"}},                       # wrong type
                       {"kit": {"tiers": None}},
                       {"kit": {"model": "anthropic/claude-sonnet-4-6"}},   # model must not count
                       {"kit": {"model": "definitely-a-real-llm", "tiers": ["static"]}}):
            self.assertEqual(d(report), "static", report)


class TestAttestFailsClosed(unittest.TestCase):
    """A payload that cannot be anchored must not be built at all.

    The on-chain attest() reverts on an empty source_hash AFTER lock_fee, so emitting one turns a
    clear local error into a wasted transaction — and the artifact is permanent and unburnable.
    """

    def _report(self, **kit):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "report.json")
        base = {"schema_version": "1.0", "kit": kit, "target": {"repo": "r", "package": "p"},
                "summary": {"overall_risk": "info", "one_liner": "x"},
                "findings": [], "checklist_coverage": [], "open_questions": []}
        if "source_hash" in kit:
            base["target"]["source_hash"] = kit.pop("source_hash")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(base, fh)
        return path

    def test_empty_source_hash_refuses(self):
        with self.assertRaises(attest.AttestationError) as ctx:
            attest.build_payload(self._report(version="0.7.1"))
        self.assertIn("source_hash", str(ctx.exception))

    def test_missing_kit_version_refuses(self):
        with self.assertRaises(attest.AttestationError) as ctx:
            attest.build_payload(self._report(source_hash="a" * 64))
        self.assertIn("kit.version", str(ctx.exception))

    def test_cli_exits_nonzero_rather_than_emitting(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "attest.py"),
                            self._report(version="0.7.1")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("::error::", r.stderr)
        self.assertNotIn("source_hash", r.stdout)


class TestSourceHashParity(unittest.TestCase):
    """sak_lib.source_hash must equal audit.sh's SOURCE_HASH, byte for byte.

    source_hash is the anchor an on-chain attestation binds to, and it is now computed in two
    places: shell (audit.sh, the clone path) and Python (sak_lib, the pip path). If they ever
    disagree, the same source attests under two different anchors and neither verifies against
    the other. This runs the actual shell pipeline rather than reimplementing it.
    """

    SHELL = r'''
    T="$1"
    declare -a TF=(); TF+=("$T/Cargo.toml")
    while IFS= read -r f; do TF+=("$f"); done < <(find "$T/src" -name "*.rs" -type f 2>/dev/null | sort)
    if [ -d "$T/tests" ]; then
      while IFS= read -r f; do TF+=("$f"); done < <(find "$T/tests" -name "*.rs" -type f 2>/dev/null | sort)
    fi
    if command -v sha256sum >/dev/null 2>&1; then
      cat "${TF[@]}" 2>/dev/null | sha256sum | cut -d" " -f1
    else
      cat "${TF[@]}" 2>/dev/null | shasum -a 256 | cut -d" " -f1
    fi
    '''

    def _shell_hash(self, pkg):
        r = subprocess.run(["bash", "-c", self.SHELL, "_", pkg], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_matches_the_shell_on_a_package_with_tests_dir(self):
        pkg = os.path.join(ROOT, "examples", "vulnerable-vault")
        self.assertEqual(sak_lib.source_hash(pkg), self._shell_hash(pkg))

    def test_matches_the_shell_on_the_attestation_blueprint(self):
        pkg = os.path.join(ROOT, "attestation")
        self.assertEqual(sak_lib.source_hash(pkg), self._shell_hash(pkg))

    def test_empty_when_nothing_readable(self):
        self.assertEqual(sak_lib.source_hash(tempfile.mkdtemp()), "")

    def test_ordering_is_cargo_then_src_then_tests(self):
        pkg = os.path.join(ROOT, "examples", "vulnerable-vault")
        files = [os.path.relpath(p, pkg) for p in sak_lib.target_files(pkg)]
        self.assertEqual(files[0], "Cargo.toml")
        srcs = [i for i, f in enumerate(files) if f.startswith("src" + os.sep)]
        tsts = [i for i, f in enumerate(files) if f.startswith("tests" + os.sep)]
        if srcs and tsts:
            self.assertLess(max(srcs), min(tsts), "src/ must precede tests/")
        self.assertEqual(srcs, sorted(srcs))


class TestBuildReportProvenance(unittest.TestCase):
    """build_report(findings, pkg_dir) must produce a report that is attestable on its own.

    This is the pip-only path docs/sdk.md documents. Without pkg_dir there is no stamper in the
    installed package, so the payload had an empty anchor and a fabricated mode.
    """

    PKG = os.path.join(ROOT, "examples", "vulnerable-vault")

    def test_stamped_report_is_attestable(self):
        report = sak_lib.build_report([], self.PKG)
        self.assertEqual(report["kit"]["tiers"], ["static"])
        self.assertTrue(report["target"]["source_hash"])
        path = os.path.join(tempfile.mkdtemp(), "report.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh)
        payload = attest.build_payload(path)
        self.assertEqual(payload["mode"], "static")   # never "hybrid" — no LLM tier ran
        self.assertEqual(payload["source_hash"], sak_lib.source_hash(self.PKG))

    def test_unstamped_report_is_refused_not_fabricated(self):
        path = os.path.join(tempfile.mkdtemp(), "report.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sak_lib.build_report([]), fh)
        with self.assertRaises(attest.AttestationError):
            attest.build_payload(path)


class TestPayloadHelpers(unittest.TestCase):
    def test_u16_clamp(self):
        self.assertEqual(attest._u16(70000), 65535)
        self.assertEqual(attest._u16(-5), 0)
        self.assertEqual(attest._u16("x"), 0)

    def test_manifest_strips_control_chars(self):
        payload = dict(attest.build_payload(SAMPLE), mode="hybrid\nCALL_METHOD evil")
        self.assertNotIn("\nCALL_METHOD evil", attest.render_manifest(payload, "c", "a"))


if __name__ == "__main__":
    unittest.main()
