"""Tests for scanner/cli.py's `scan` and `render` subcommands -- the real production write
path, which had ZERO test coverage before this file. Deleting the gate from `cmd_scan` (so the
unredacted report lands in the tracked, public `scanner/results/` directory) or from
`cmd_render` (so `python3 -m scanner.cli render results-full/<date>.json` prints full rows for
a withheld third party) would both leave every other test in this suite green: `cmd_scan` and
`cmd_render` are exercised nowhere else.

The network is fully stubbed -- `report_mod.run_scan` itself is replaced with a canned report
producer, so nothing here makes (or could make) a live Gateway call; mainnet is halted anyway.
`DEFAULT_RESULTS_DIR`/`DEFAULT_FULL_RESULTS_DIR` are patched to temp directories so a run never
touches the real, tracked `scanner/results/` tree.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanner import cli  # noqa: E402
from scanner import models  # noqa: E402
from scanner import report as report_mod  # noqa: E402
from scanner import site as site_mod  # noqa: E402

SECRET_REASON = "confirmed drain path: reentrant withdraw via an unchecked callback"
SECRET_EVIDENCE = "vault_component_rdx1_holds_the_live_bug"
EMBARGO_HOLD_REASON_TEXT = "reported to the maintainer 2026-09-08"
# A synthetic stand-in for a withheld third party. Deliberately not a real project's name.
THIRD_PARTY_PROJECT = "Example Pool Co"
THIRD_PARTY_ID = "third-party-entity"
THIRD_PARTY_NOTE = (
    f"This cohort includes the {THIRD_PARTY_PROJECT} pool, a third party we do not operate."
)

GUILD_ADDRESS = "component_rdx1" + "g" * 40
THIRD_PARTY_ADDRESS = "component_rdx1" + "o" * 40


def _stub_report(generated_at="2026-09-08T00:00:00Z"):
    """A minimal, schema-shaped report carrying exactly the two things a leak would show up
    in: an embargoed finding on our own entity, and a third-party entity beside it."""
    embargoed_check = models.make_finding(
        "owner_role", "fail", "critical", SECRET_REASON, {"path": SECRET_EVIDENCE}, 1,
        embargo=models.embargoed(EMBARGO_HOLD_REASON_TEXT, "2026-12-01T00:00:00Z"),
    )
    public_guild_check = models.make_finding(
        "metadata_claims", "pass", "none", "Metadata is complete.", {"k": "v"}, 1,
    )
    public_third_party_check = models.make_finding(
        "owner_role", "fail", "high", "This third-party finding's reason is itself public.",
        {"k": "v"}, 1,
    )
    return {
        "schema_version": "1.0",
        "scan_id": f"stub-{generated_at}",
        "generated_at": generated_at,
        "network": "mainnet",
        "gateway": {
            "url": "https://mainnet.radixdlt.com",
            "pinned_state_version": 1,
            "pinned_proposer_round_timestamp": None,
            "halted": False,
            "halt_detail": None,
        },
        "cohort_source": "scanner/data/cohort.json",
        "notes": [THIRD_PARTY_NOTE],
        "entities": [
            {
                "id": "guild-entity",
                "project": site_mod.OWN_PROJECT,
                "category": "guild",
                "address": GUILD_ADDRESS,
                "entity_kind": "component",
                "label": "A Guild component",
                "checks": [embargoed_check, public_guild_check],
            },
            {
                "id": THIRD_PARTY_ID,
                "project": THIRD_PARTY_PROJECT,
                "category": "external",
                "address": THIRD_PARTY_ADDRESS,
                "entity_kind": "component",
                "label": "A third-party pool we do not operate",
                "checks": [public_third_party_check],
            },
        ],
    }


def _write_cohort(path):
    cohort = {
        "notes": [],
        "entities": [
            {
                "id": "guild-entity", "project": site_mod.OWN_PROJECT, "category": "guild",
                "address": GUILD_ADDRESS, "entity_kind": "component", "label": "A Guild component",
            },
            {
                "id": THIRD_PARTY_ID, "project": THIRD_PARTY_PROJECT, "category": "external",
                "address": THIRD_PARTY_ADDRESS, "entity_kind": "component",
                "label": "A third-party pool we do not operate",
            },
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cohort, fh)


class CmdScanGatesThePublicWriteTest(unittest.TestCase):
    """cmd_scan is what `make scan` actually runs. It must never let an embargoed finding or
    a third-party entity reach the tracked scanner/results/ directory, the full-detail copy
    it writes alongside that must keep the real values, and Check 4's baseline lookup must
    keep reading the full-detail directory, never the redacted one."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # Deliberately not one a substring of the other ("results"/"results-full" would be),
        # so a test asserting "the full dir, not the public dir" can't pass by accident.
        self.public_dir = os.path.join(self.tmp, "pub")
        self.full_dir = os.path.join(self.tmp, "full")
        self.cohort_path = os.path.join(self.tmp, "cohort.json")
        _write_cohort(self.cohort_path)

        self.stub_report = _stub_report()
        patch_public = patch.object(cli, "DEFAULT_RESULTS_DIR", self.public_dir)
        patch_full = patch.object(cli, "DEFAULT_FULL_RESULTS_DIR", self.full_dir)
        patch_scan = patch.object(report_mod, "run_scan", return_value=self.stub_report)
        for p in (patch_public, patch_full, patch_scan):
            p.start()
            self.addCleanup(p.stop)

    def _run_scan(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = cli.main(["scan", "--cohort", self.cohort_path, "--network", "mainnet"])
        self.assertEqual(rc, 0)
        return stderr.getvalue()

    def test_public_results_file_is_gated(self):
        self._run_scan()
        public_path = os.path.join(self.public_dir, "2026-09-08.json")
        with open(public_path, encoding="utf-8") as fh:
            public_content = fh.read()
        self.assertNotIn(SECRET_REASON, public_content)
        self.assertNotIn(SECRET_EVIDENCE, public_content)
        self.assertNotIn(EMBARGO_HOLD_REASON_TEXT, public_content)
        self.assertNotIn(THIRD_PARTY_PROJECT, public_content)
        self.assertNotIn(THIRD_PARTY_ID, public_content)
        self.assertNotIn(THIRD_PARTY_ADDRESS, public_content)

        public_report = json.loads(public_content)
        self.assertEqual(len(public_report["entities"]), 1)
        self.assertEqual(public_report["entities"][0]["id"], "guild-entity")

        # Byte-identical to what the gate itself produces from the same raw report -- this is
        # the assertion that fails the moment cmd_scan's write path stops calling the gate.
        self.assertEqual(
            public_content,
            report_mod.dump_report(site_mod.redact_for_publication(self.stub_report)),
        )

    def test_full_detail_file_keeps_the_real_values(self):
        self._run_scan()
        full_path = os.path.join(self.full_dir, "2026-09-08.json")
        with open(full_path, encoding="utf-8") as fh:
            full_content = fh.read()
        self.assertIn(SECRET_REASON, full_content)
        self.assertIn(SECRET_EVIDENCE, full_content)
        self.assertIn(THIRD_PARTY_PROJECT, full_content)

        full_report = json.loads(full_content)
        self.assertEqual(len(full_report["entities"]), 2)

    def test_baseline_lookup_reads_the_full_detail_directory_not_the_public_one(self):
        # Seed a "prior scan" only where a real second run would ever find one: the
        # full-detail directory cmd_scan itself writes to.
        os.makedirs(self.full_dir, exist_ok=True)
        prior_path = os.path.join(self.full_dir, "2026-09-01.json")
        report_mod.write_report(prior_path, _stub_report(generated_at="2026-09-01T00:00:00Z"))

        stderr_output = self._run_scan()
        baseline_lines = [
            line for line in stderr_output.splitlines() if line.startswith("Using baseline:")
        ]
        self.assertEqual(len(baseline_lines), 1)
        self.assertIn(self.full_dir, baseline_lines[0])
        self.assertNotIn(self.public_dir, baseline_lines[0])


SECOND_THIRD_PARTY_ADDRESS = "component_rdx1" + "z" * 40


def _report_for_entities(entities, cohort_source, generated_at="2026-09-08T00:00:00Z"):
    """A minimal, schema-shaped report covering exactly `entities` (cohort dicts, as loaded by
    cohort.load_cohort) -- used to stand in for report_mod.run_scan's real return value so
    CmdScanCohortSelectionTest can assert on which cohort was actually passed through to it,
    without needing a real check run. `cohort_source` mirrors the real run_scan's own
    behaviour: whatever cmd_scan passed as its `cohort_source` kwarg ends up in the field
    verbatim.
    """
    return {
        "schema_version": "1.0",
        "scan_id": f"stub-{generated_at}",
        "generated_at": generated_at,
        "network": "mainnet",
        "gateway": {
            "url": "https://mainnet.radixdlt.com", "pinned_state_version": 1,
            "pinned_proposer_round_timestamp": None, "halted": False, "halt_detail": None,
        },
        "cohort_source": cohort_source,
        "notes": [],
        "entities": [
            {
                "id": e["id"], "project": e["project"], "category": e["category"],
                "address": e["address"], "entity_kind": e["entity_kind"], "label": e["label"],
                "checks": [models.make_finding("metadata_claims", "pass", "none", "ok", {"k": "v"}, 1)],
            }
            for e in entities
        ],
    }


class CmdScanCohortSelectionTest(unittest.TestCase):
    """cmd_scan's default (no --cohort) cohort selection: read the full local cohort when it
    exists on disk, falling back to the public one otherwise -- and a published report's
    cohort_source must never name the gitignored full cohort's own path either way."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.public_dir = os.path.join(self.tmp, "pub")
        self.full_results_dir = os.path.join(self.tmp, "full")
        self.public_cohort_path = os.path.join(self.tmp, "cohort.json")
        self.full_cohort_path = os.path.join(self.tmp, "cohort-full.json")

        _write_cohort(self.public_cohort_path)  # 2 entities: one Guild, one third party

        full_cohort = {
            "notes": [],
            "entities": [
                {"id": "guild-entity", "project": site_mod.OWN_PROJECT, "category": "guild",
                 "address": GUILD_ADDRESS, "entity_kind": "component", "label": "A Guild component"},
                {"id": THIRD_PARTY_ID, "project": THIRD_PARTY_PROJECT, "category": "external",
                 "address": THIRD_PARTY_ADDRESS, "entity_kind": "component",
                 "label": "A third-party pool we do not operate"},
                {"id": "second-third-party", "project": "A Second External Project", "category": "external",
                 "address": SECOND_THIRD_PARTY_ADDRESS, "entity_kind": "component",
                 "label": "A project only the full cohort knows about"},
            ],
        }
        with open(self.full_cohort_path, "w", encoding="utf-8") as fh:
            json.dump(full_cohort, fh)

        patches = [
            patch.object(cli, "DEFAULT_COHORT_PATH", self.public_cohort_path),
            patch.object(cli, "DEFAULT_FULL_COHORT_PATH", self.full_cohort_path),
            patch.object(cli, "_PUBLIC_COHORT_SOURCE", "scanner/data/cohort.json"),
            patch.object(cli, "DEFAULT_RESULTS_DIR", self.public_dir),
            patch.object(cli, "DEFAULT_FULL_RESULTS_DIR", self.full_results_dir),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        self.captured = {}

        def _capturing_run_scan(cohort_path, entities, **kwargs):
            self.captured["cohort_path"] = cohort_path
            self.captured["entities"] = entities
            cohort_source = kwargs.get("cohort_source")
            self.captured["cohort_source_kwarg"] = cohort_source
            # Mirror run_scan's own default: an unset override falls back to a repo-relative
            # form of cohort_path, same as report._repo_relative would produce.
            resolved_source = cohort_source if cohort_source is not None else os.path.relpath(cohort_path, report_mod._REPO_ROOT)
            return _report_for_entities(entities, resolved_source)

        patch_run_scan = patch.object(report_mod, "run_scan", side_effect=_capturing_run_scan)
        patch_run_scan.start()
        self.addCleanup(patch_run_scan.stop)

    def _run_scan(self, extra_args=()):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = cli.main(["scan", "--network", "mainnet", *extra_args])
        self.assertEqual(rc, 0)
        return stderr.getvalue()

    def test_reads_the_full_cohort_when_present(self):
        self._run_scan()
        self.assertEqual(self.captured["cohort_path"], self.full_cohort_path)
        self.assertEqual(len(self.captured["entities"]), 3)

    def test_cohort_source_override_names_the_public_path_when_full_cohort_is_used(self):
        self._run_scan()
        self.assertEqual(self.captured["cohort_source_kwarg"], "scanner/data/cohort.json")
        self.assertNotIn("cohort-full", self.captured["cohort_source_kwarg"])

    def test_falls_back_to_the_public_cohort_when_no_full_cohort_file_exists(self):
        os.remove(self.full_cohort_path)
        self._run_scan()
        self.assertEqual(self.captured["cohort_path"], self.public_cohort_path)
        self.assertEqual(len(self.captured["entities"]), 2)

    def test_no_source_override_when_falling_back_to_the_public_cohort(self):
        os.remove(self.full_cohort_path)
        self._run_scan()
        self.assertIsNone(self.captured["cohort_source_kwarg"])

    def test_explicit_cohort_flag_is_exact_no_fallback_no_source_override(self):
        # --cohort is exact even when it happens to point at the full cohort: no fallback
        # logic applies, and cohort_source is left to its normal (non-overridden) default.
        self._run_scan(extra_args=["--cohort", self.full_cohort_path])
        self.assertEqual(self.captured["cohort_path"], self.full_cohort_path)
        self.assertIsNone(self.captured["cohort_source_kwarg"])

    def test_published_report_cohort_source_is_never_the_gitignored_path(self):
        # End-to-end: the file cmd_scan actually writes to the public results dir must carry
        # a cohort_source a stranger reading the repo could resolve, not the local full cohort.
        self._run_scan()
        public_path = os.path.join(self.public_dir, "2026-09-08.json")
        with open(public_path, encoding="utf-8") as fh:
            written = json.load(fh)
        self.assertEqual(written["cohort_source"], "scanner/data/cohort.json")


class CmdRenderGatesItsInputTest(unittest.TestCase):
    """`python3 -m scanner.cli render` accepts any report.json path -- including
    results-full/<date>.json, Check 4's own baseline source. It must apply the same
    publication gate build() does rather than rendering whatever it's pointed at verbatim."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.raw_path = os.path.join(self.tmp, "raw.json")
        report_mod.write_report(self.raw_path, _stub_report())
        self.out_path = os.path.join(self.tmp, "out.md")

    def test_render_gates_a_raw_unredacted_report(self):
        rc = cli.main(["render", self.raw_path, "--out", self.out_path])
        self.assertEqual(rc, 0)
        with open(self.out_path, encoding="utf-8") as fh:
            md = fh.read()
        self.assertNotIn(SECRET_REASON, md)
        self.assertNotIn(SECRET_EVIDENCE, md)
        self.assertNotIn(EMBARGO_HOLD_REASON_TEXT, md)
        self.assertNotIn(THIRD_PARTY_PROJECT, md)
        self.assertNotIn(THIRD_PARTY_ID, md)
        self.assertNotIn(THIRD_PARTY_ADDRESS, md)

    def test_render_still_shows_the_published_entity_and_its_findings(self):
        cli.main(["render", self.raw_path, "--out", self.out_path])
        with open(self.out_path, encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("A Guild component", md)
        self.assertIn("FAIL", md)


if __name__ == "__main__":
    unittest.main()
