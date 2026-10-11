"""Integration test for scanner/report.py's run_scan() orchestration: cohort loading, the
gateway-status pin, the halt probe, the two-hop dApp-Definition fetch, and wiring a baseline
report into Check 4 -- all exercised together against the recorded fixture captures, with only the
network layer (scanner.gateway's three Gateway-calling functions) mocked out.

The cohort itself is NOT the real, committed scanner/data/cohort.json: that file is the public
cohort (the Guild's own entities only, see tests/test_scanner_cohort.py), and this class needs
the full seven-entity shape -- external projects, a two-hop dApp-Definition fetch, a package
whose upgrade-baseline continuity gets exercised -- to cover run_scan()'s logic at all. That
full-cohort shape lives in the gitignored scanner/data/cohort-full.json when an operator has one
locally, but a test file must pass identically on a plain clone that never has it, so the
fixture is defined here instead (_FULL_COHORT_PATH, below), independent of whatever cohort files
happen to exist on disk.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanner import cohort as cohort_mod  # noqa: E402
from scanner import diff as diff_mod  # noqa: E402
from scanner import models  # noqa: E402
from scanner import report as report_mod  # noqa: E402

FIXTURES = os.path.join(ROOT, "examples", "posture-scanner")

# The same seven-entity shape scanner/data/cohort.json carried before the public/full cohort
# split -- see this module's own docstring for why it is defined here rather than read off
# disk. Addresses match the recorded Gateway fixtures in FIXTURES/_FIXTURE_FILES below.
_FULL_COHORT_ENTITIES = [
    {
        "id": "extern-a-pool", "project": "External A", "category": "external",
        "address": "component_rdx1cpmgqg4cuq54a74kl38g03wfxjsq9w02e8twt79jlh0sw4qpnrylpj",
        "entity_kind": "component", "label": "External Pool A",
    },
    {
        "id": "extern-a-package", "project": "External A", "category": "external",
        "address": "package_rdx1pkueysly7fwkpsuqs7kptveqpx7ehmwgrgp23szgyeyhc2w29es6zc",
        "entity_kind": "package", "label": "External Pool A package (Pool blueprint)",
    },
    {
        "id": "extern-c-pool", "project": "External C", "category": "external",
        "address": "component_rdx1cqu5uxws3erxzd0vmesjytgvltftpjr53t4zcf4c24d704zchjxrvv",
        "entity_kind": "component", "label": "External Pool C (XRD-token WeightedPool)",
    },
    {
        "id": "extern-b-token", "project": "External B", "category": "external",
        "address": "resource_rdx1t5deegdjgx93jtmm5vlf6xw84n4ppzkcq2r2c768zpkl2v3x8yry0s",
        "entity_kind": "resource", "label": "Bridged Token B (external-issued wrapped stablecoin)",
    },
    {
        "id": "guild-dapp-definition-account", "project": "Radix Guild", "category": "guild",
        "address": "account_rdx12yh4fwevmvnqgd3ppzau66cm9xu874srmrt9g2cye3fa8j8y78z9sq",
        "entity_kind": "account", "label": "Radix Guild dApp Definition account",
        "role": "dapp_definition_hub",
    },
    {
        "id": "guild-badge-manager", "project": "Radix Guild", "category": "guild",
        "address": "component_rdx1czexylvvm0q4uhwpjaqmlznj9sd3y2jnmmah6qug9lm9sfm3tyrtva",
        "entity_kind": "component", "label": "Guild Badge Manager",
    },
    {
        "id": "guild-badge-factory", "project": "Radix Guild", "category": "guild",
        "address": "component_rdx1cqlakjp65k8zkznynynsqpjcu7fwt9zcdvee358p948wp9h4n2km99",
        "entity_kind": "component", "label": "Guild Badge Factory",
    },
]

_FULL_COHORT_NOTES = [
    "Fixture note for run_scan()'s own tests: this cohort deliberately includes External B's "
    "bridged-token resource so test_echoes_cohort_level_notes can prove cohort-level notes reach "
    "the report unchanged.",
]


def _write_full_cohort():
    tmpdir = tempfile.mkdtemp(prefix="sak-full-cohort-")
    path = os.path.join(tmpdir, "cohort-full.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"notes": _FULL_COHORT_NOTES, "entities": _FULL_COHORT_ENTITIES}, fh)
    return path


COHORT_PATH = _write_full_cohort()

_FIXTURE_FILES = [
    "component_extern_a_pool.json", "package_extern_a.json", "component_extern_c_pool.json",
    "resource_extern_b_token.json", "account_guild_dapp_definition.json", "component_guild_badge_manager.json",
    "component_guild_badge_factory.json", "account_extern_a_dapp_definition.json",
    "account_extern_b_dapp_definition.json",
]


def _load_master_map():
    master = {}
    for name in _FIXTURE_FILES:
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
            item = json.load(fh)["items"][0]
        master[item["address"]] = item
    return master


MASTER = _load_master_map()

FAKE_GATEWAY_STATUS = {
    "ledger_state": {
        "network": "mainnet", "state_version": 557840622,
        "proposer_round_timestamp": "2026-08-31T21:19:06.179Z", "epoch": 339896, "round": 102,
    },
    "release_info": {"release_version": "1.10.6-v1.10.7"},
}


def _fake_entity_details_by_address(addresses, state_version, base_url=None):
    return {addr: MASTER[addr] for addr in addresses}


class TestRunScan(unittest.TestCase):
    def setUp(self):
        self.cohort = cohort_mod.load_cohort(COHORT_PATH)
        patcher_status = patch("scanner.gateway.gateway_status", return_value=FAKE_GATEWAY_STATUS)
        patcher_halt = patch("scanner.gateway.probe_halted", return_value=(True, "NotSyncedUpError: ... 7 days ... behind"))
        patcher_details = patch("scanner.gateway.entity_details_by_address", side_effect=_fake_entity_details_by_address)
        self.addCleanup(patcher_status.stop)
        self.addCleanup(patcher_halt.stop)
        self.addCleanup(patcher_details.stop)
        patcher_status.start()
        patcher_halt.start()
        self.mock_details = patcher_details.start()

    def test_scans_all_seven_cohort_entities_with_five_checks_each(self):
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        self.assertEqual(result["schema_version"], "1.0")
        self.assertEqual(len(result["entities"]), 7)
        for entity in result["entities"]:
            check_names = {c["check"] for c in entity["checks"]}
            self.assertEqual(check_names, set(models.CHECKS))

    def test_pins_state_version_from_gateway_status(self):
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        self.assertEqual(result["gateway"]["pinned_state_version"], 557840622)
        for entity in result["entities"]:
            for c in entity["checks"]:
                self.assertEqual(c["state_version"], 557840622)

    def test_records_halt_status_and_note(self):
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        self.assertTrue(result["gateway"]["halted"])
        self.assertTrue(any("halted" in n for n in result["notes"]))

    def test_echoes_cohort_level_notes(self):
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        self.assertTrue(any("External B" in n for n in result["notes"]))

    def test_fetches_second_hop_dapp_definition_accounts_not_in_cohort(self):
        report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        # First call: the 7 cohort addresses. Second call: the two claimed hub accounts that are
        # NOT first-class cohort rows (External A's and External B's own dApp Definition accounts).
        self.assertEqual(self.mock_details.call_count, 2)
        second_call_addresses = set(self.mock_details.call_args_list[1][0][0])
        self.assertEqual(second_call_addresses, {
            "account_rdx12yvnm9jmj5phn0t6fkjcke3xpcg5f790cawrggn82xjzeyh0knz6jn",
            "account_rdx1cxkvlxd9lp246pum9yj6xhl7qg5suecljg4n62naf8dmecc5a9fwlm",
        })

    def test_external_entities_show_the_real_half_pair_gap(self):
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        by_id = {e["id"]: e for e in result["entities"]}
        pool_dapp_def = next(c for c in by_id["extern-a-pool"]["checks"] if c["check"] == "dapp_definition_two_way")
        self.assertEqual(pool_dapp_def["status"], "fail")

    def test_guild_entities_are_not_exempted_from_their_own_gap(self):
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        by_id = {e["id"]: e for e in result["entities"]}
        badge_manager_check = next(
            c for c in by_id["guild-badge-manager"]["checks"] if c["check"] == "dapp_definition_two_way"
        )
        self.assertEqual(badge_manager_check["status"], "fail")

    def test_first_scan_upgrade_check_is_baseline_informational(self):
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        by_id = {e["id"]: e for e in result["entities"]}
        pkg_upgrade = next(c for c in by_id["extern-a-package"]["checks"] if c["check"] == "package_upgrade")
        self.assertEqual(pkg_upgrade["status"], "informational")
        self.assertIn("baseline", pkg_upgrade["reason"])

    def test_second_scan_against_first_as_baseline_shows_no_change(self):
        first = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        second = report_mod.run_scan(COHORT_PATH, self.cohort, previous_report=first, generated_at="2026-09-15T09:15:00Z")

        by_id = {e["id"]: e for e in second["entities"]}
        pkg_upgrade = next(c for c in by_id["extern-a-package"]["checks"] if c["check"] == "package_upgrade")
        self.assertEqual(pkg_upgrade["status"], "pass")

        d = diff_mod.diff_reports(first, second)
        upgrade_changes = [c for c in d["changes"] if c["check"] == "package_upgrade"]
        # Every package_upgrade finding legitimately changes status (informational -> pass) on
        # the second run even though nothing on-chain moved -- that's the diff correctly
        # reporting "the scanner's own claim strengthened from baseline to confirmed-unchanged",
        # not a false "something changed on-chain" signal. Everything else must be identical.
        non_upgrade_changes = [c for c in d["changes"] if c["check"] != "package_upgrade"]
        self.assertEqual(non_upgrade_changes, [])

    def test_write_and_load_report_round_trips(self):
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        out_path = os.path.join(HERE, "_tmp_report_roundtrip.json")
        self.addCleanup(lambda: os.path.exists(out_path) and os.remove(out_path))
        report_mod.write_report(out_path, result)
        loaded = report_mod.load_report(out_path)
        self.assertEqual(loaded, result)

    def test_dump_report_matches_the_bytes_write_report_puts_on_disk(self):
        # scanner.site.build() derives latest.json from dump_report(gated) rather than
        # re-opening a file -- this is the guarantee that keeps it byte-identical to what
        # write_report would have put on disk for the same dict.
        result = report_mod.run_scan(COHORT_PATH, self.cohort, generated_at="2026-09-08T09:15:00Z")
        out_path = os.path.join(HERE, "_tmp_report_dump.json")
        self.addCleanup(lambda: os.path.exists(out_path) and os.remove(out_path))
        report_mod.write_report(out_path, result)
        with open(out_path, encoding="utf-8") as fh:
            written = fh.read()
        self.assertEqual(report_mod.dump_report(result), written)


SCHEMA_PATH = os.path.join(ROOT, "schema", "posture-scan-report.schema.json")
FIRST_SCAN_PATH = os.path.join(ROOT, "scanner", "results", "2026-09-08.json")


class TestSchemaAndCommittedFirstScan(unittest.TestCase):
    """jsonschema is an optional extra (pip install ".[schema]"), same as the rest of the kit --
    these tests skip cleanly rather than failing when it's absent, matching bin/dapp_scope.py's
    own fallback discipline (see tests/test_dapp_scope.py for the sibling pattern).
    """

    def setUp(self):
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest("jsonschema not installed (pip install '.[schema]')")

    def test_schema_file_is_valid_json_schema(self):
        import jsonschema
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_committed_first_scan_validates_against_the_schema(self):
        import jsonschema
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        with open(FIRST_SCAN_PATH, encoding="utf-8") as fh:
            first_scan = json.load(fh)
        jsonschema.Draft202012Validator(schema).validate(first_scan)

    def test_committed_first_scan_has_three_published_entities_with_five_checks_each(self):
        # The cohort this scan actually ran was seven entities (see
        # test_scans_all_seven_cohort_entities_with_five_checks_each, above, against the raw
        # scan). This committed file is the PUBLIC one, though, and scanner.site.
        # redact_for_publication withholds every entity whose project isn't Radix Guild
        # entirely -- three of the seven -- so this is 3, not 7. See scanner/site.py.
        with open(FIRST_SCAN_PATH, encoding="utf-8") as fh:
            first_scan = json.load(fh)
        self.assertEqual(len(first_scan["entities"]), 3)
        for entity in first_scan["entities"]:
            self.assertEqual(entity["project"], "Radix Guild")
            self.assertEqual({c["check"] for c in entity["checks"]}, set(models.CHECKS))

    def test_committed_first_scan_shows_the_guild_is_not_exempted(self):
        with open(FIRST_SCAN_PATH, encoding="utf-8") as fh:
            first_scan = json.load(fh)
        by_id = {e["id"]: e for e in first_scan["entities"]}
        for guild_id in ("guild-badge-manager", "guild-badge-factory"):
            dapp_def = next(c for c in by_id[guild_id]["checks"] if c["check"] == "dapp_definition_two_way")
            self.assertEqual(dapp_def["status"], "fail")


FIRST_SCAN_MD_PATH = os.path.join(ROOT, "scanner", "results", "2026-09-08.md")


class RenderMarkdownTest(unittest.TestCase):
    """render_markdown() must mirror the JSON exactly: never soften a fail, never omit an
    entity, and stay a pure function of the report dict (no Gateway, no clock)."""

    @classmethod
    def setUpClass(cls):
        with open(FIRST_SCAN_PATH, encoding="utf-8") as fh:
            cls.report = json.load(fh)
        cls.md = report_mod.render_markdown(cls.report)

    def test_every_entity_appears_in_the_rendered_table(self):
        for entity in self.report["entities"]:
            self.assertIn(entity["label"], self.md)

    def test_every_fail_is_rendered_as_fail_never_softened(self):
        fail_reasons = [
            c["reason"]
            for e in self.report["entities"]
            for c in e["checks"]
            if c["status"] == "fail"
        ]
        self.assertTrue(fail_reasons, "fixture should contain at least one fail")
        for reason in fail_reasons:
            self.assertIn(reason, self.md)
        # The count in the headline must equal the real number of fails.
        self.assertIn(f"**{len(fail_reasons)} failing check", self.md)

    def test_halt_banner_shown_when_halted(self):
        self.assertTrue(self.report["gateway"]["halted"])
        self.assertIn("network was halted", self.md)
        self.assertIn(str(self.report["gateway"]["pinned_state_version"]), self.md)

    def test_cohort_notes_are_carried_verbatim(self):
        for note in self.report["notes"]:
            self.assertIn(note, self.md)

    def test_render_is_pure_no_network_import_needed(self):
        # Rendering must not touch the gateway module; prove it by rendering with the
        # gateway module's network functions patched to raise.
        with patch.object(report_mod.gateway, "gateway_status", side_effect=AssertionError("network touched")), \
             patch.object(report_mod.gateway, "entity_details_by_address", side_effect=AssertionError("network touched")):
            again = report_mod.render_markdown(self.report)
        self.assertEqual(again, self.md)

    def test_committed_md_is_in_sync_with_committed_json(self):
        # The committed .md must be exactly what the renderer produces from the committed
        # .json, so the page can never silently drift from the machine-readable source.
        with open(FIRST_SCAN_MD_PATH, encoding="utf-8") as fh:
            committed = fh.read()
        self.assertEqual(committed, self.md, "regenerate: python3 -m scanner.cli render scanner/results/2026-09-08.json --out scanner/results/2026-09-08.md")


if __name__ == "__main__":
    unittest.main()
