"""Tests for scanner/site.py — the public status page.

The page is the only artefact a stranger will ever read, so the properties worth testing
are the ones that would mislead them: a page that has drifted from the report it claims
to render, a `fail` that quietly stopped appearing, and — the one that actually matters —
an embargoed finding whose detail leaked onto a public URL.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanner import models  # noqa: E402
from scanner import report as report_mod  # noqa: E402
from scanner import site  # noqa: E402

RESULTS = os.path.join(ROOT, "scanner", "results")
PAGE = os.path.join(ROOT, "docs", "index.html")

SECRET_REASON = "drain manifest: call withdraw_all with a forged proof"
SECRET_EVIDENCE = "component_rdx1_the_vulnerable_one"


def _embargoed_report():
    """A minimal report carrying one embargoed finding beside one public one."""
    return {
        "schema_version": "1.0",
        "scan_id": "test-embargo",
        "generated_at": "2026-09-08T00:00:00Z",
        "network": "mainnet",
        "gateway": {"url": "https://mainnet.radixdlt.com", "pinned_state_version": 1, "halted": False},
        "notes": [],
        "entities": [
            {
                "id": "e1",
                "project": "Someone Else",
                "category": "external",
                "address": "component_rdx1" + "a" * 40,
                "entity_kind": "component",
                "label": "A component with a real hole in it",
                "checks": [
                    {
                        "check": "owner_role",
                        "status": "fail",
                        "severity": "critical",
                        "reason": SECRET_REASON,
                        "evidence": {"path": SECRET_EVIDENCE},
                        "embargo": {
                            "status": "embargoed",
                            "publish_at": "2026-10-08T00:00:00Z",
                            "reason": "reported to the maintainer 2026-09-08",
                        },
                        "state_version": 1,
                    },
                    {
                        "check": "metadata_claims",
                        "status": "pass",
                        "severity": "none",
                        "reason": "Metadata is complete.",
                        "evidence": {},
                        "embargo": {"status": "public", "publish_at": None, "reason": None},
                        "state_version": 1,
                    },
                ],
            }
        ],
    }


class EmbargoTest(unittest.TestCase):
    """The line between an instrument and a zero-day broadcast."""

    def test_embargoed_detail_never_reaches_the_page(self):
        page = site.render_html(_embargoed_report())
        self.assertNotIn(SECRET_REASON, page)
        self.assertNotIn(SECRET_EVIDENCE, page)

    def test_embargoed_finding_still_states_that_it_exists(self):
        page = site.render_html(_embargoed_report())
        # Existence, severity and the publish clock are publishable; the detail is not.
        self.assertIn("FAIL", page)
        self.assertIn("critical", page)
        self.assertIn("2026-10-08T00:00:00Z", page)

    def test_a_missing_embargo_block_fails_closed(self):
        report = _embargoed_report()
        del report["entities"][0]["checks"][0]["embargo"]
        page = site.render_html(report)
        self.assertNotIn(SECRET_REASON, page)

    def test_public_findings_do_publish_their_reason(self):
        page = site.render_html(_embargoed_report())
        self.assertIn("Metadata is complete.", page)

    def test_a_truthy_non_dict_embargo_fails_closed_without_crashing(self):
        # `check.get("embargo") or {}` only catches a falsy embargo (None/{}/""); a truthy
        # non-dict -- a bare string, say -- stays exactly as truthy, so that pattern leaves it
        # unchanged and the `.get("publish_at")` right after it raises AttributeError. This is
        # models.is_public's own fail-closed case (it already returns False here via
        # isinstance) -- render_html must survive it, not crash while doing the right thing.
        report = _embargoed_report()
        report["entities"][0]["checks"][0]["embargo"] = "not a dict"
        page = site.render_html(report)  # must not raise
        self.assertNotIn(SECRET_REASON, page)
        self.assertNotIn(SECRET_EVIDENCE, page)

    def test_a_truthy_non_empty_list_embargo_fails_closed_without_crashing(self):
        report = _embargoed_report()
        report["entities"][0]["checks"][0]["embargo"] = ["also not a dict"]
        page = site.render_html(report)  # must not raise
        self.assertNotIn(SECRET_REASON, page)
        self.assertNotIn(SECRET_EVIDENCE, page)


class FidelityTest(unittest.TestCase):
    """The page mirrors the report; it never re-derives or softens a status."""

    def setUp(self):
        with open(site.newest_dated_report(RESULTS), encoding="utf-8") as handle:
            self.report = json.load(handle)
        self.page = site.render_html(self.report)

    def test_every_failing_check_appears_on_the_page(self):
        fails = sum(
            1
            for entity in self.report["entities"]
            for check in entity["checks"]
            if check["status"] == "fail"
        )
        # Each fail renders one pill in the table and one in the findings list. Count the
        # pill markup, not the word — the legend prose says "FAIL" too.
        self.assertEqual(self.page.count('class="pill s-fail"'), fails * 2)
        self.assertGreater(fails, 0, "the fixture report should carry real failures")

    def test_every_entity_appears(self):
        for entity in self.report["entities"]:
            self.assertIn(entity["address"], self.page)

    def test_render_is_deterministic(self):
        self.assertEqual(self.page, site.render_html(self.report))

    def test_halt_state_is_stated_when_the_scan_was_halted(self):
        if self.report["gateway"].get("halted"):
            self.assertIn("halted when this scan ran", self.page)
            self.assertIn(str(self.report["gateway"]["pinned_state_version"]), self.page)


def _snapshot_report(gateway_overrides=None, omit_halted_field=False):
    """A minimal report carrying no entities, just enough of `gateway` to exercise the
    pinned-snapshot banner (site._pinned_snapshot_banner) in isolation from everything else
    render_html does. `omit_halted_field` drops `halted` entirely, rather than setting it
    False, to cover a report shape the schema forbids (halted is required) but the renderer
    must still survive per its own defensive style (see is_public, redact_embargo).
    """
    gateway = {
        "url": "https://mainnet.radixdlt.com",
        "pinned_state_version": 557840622,
        "pinned_proposer_round_timestamp": "2026-08-31T21:19:06.179Z",
        "halted": True,
        "halt_detail": None,
    }
    if omit_halted_field:
        del gateway["halted"]
    gateway.update(gateway_overrides or {})
    return {
        "schema_version": "1.0",
        "scan_id": "test-snapshot-banner",
        "generated_at": "2026-09-08T00:00:00Z",
        "network": "mainnet",
        "gateway": gateway,
        "notes": [],
        "entities": [],
    }


class PinnedSnapshotBannerTest(unittest.TestCase):
    """The banner the page must carry: a reader arriving well
    after a long halt must not be able to mistake a pinned snapshot for a current read. Every
    fact in it must come from `report["gateway"]` alone -- no clock, no network (site.py's own
    module docstring, property 3) -- so these tests feed synthetic gateway blocks rather than
    reading any live state.
    """

    def test_states_the_exact_pinned_state_version_comma_grouped(self):
        page = site.render_html(_snapshot_report())
        self.assertIn("557,840,622", page)

    def test_states_the_ledger_timestamp_in_friendly_form(self):
        page = site.render_html(_snapshot_report())
        self.assertIn("2026-08-31 21:19 UTC", page)

    def test_halted_sentence_present_when_report_says_halted(self):
        page = site.render_html(_snapshot_report({"halted": True}))
        self.assertIn("had not produced a newer state when the scan ran", page)
        self.assertIn("are not refreshed automatically", page)

    def test_halted_sentence_absent_when_report_says_not_halted(self):
        page = site.render_html(_snapshot_report({"halted": False}))
        self.assertNotIn("had not produced a newer state when the scan ran", page)
        # (a) and (b) still render -- only the halted-specific claim (c) is conditional.
        self.assertIn("557,840,622", page)
        self.assertIn("2026-08-31 21:19 UTC", page)
        # The generic, halt-agnostic fallback sentence takes its place.
        self.assertIn("not the ledger as it is now", page)

    def test_generic_sentence_used_when_report_has_no_liveness_field_at_all(self):
        # "derive nothing" -- a report shape without gateway.halted must not be read as
        # either halted or live; it gets the same fixed sentence as an explicit False.
        page = site.render_html(_snapshot_report(omit_halted_field=True))
        self.assertNotIn("had not produced a newer state when the scan ran", page)
        self.assertIn("not the ledger as it is now", page)
        self.assertIn("557,840,622", page)

    def test_banner_appears_near_the_top_before_the_state_bar(self):
        page = site.render_html(_snapshot_report())
        self.assertLess(
            page.index('class="pin'), page.index('class="state'),
            "the pinned-snapshot banner must render above the stats bar, not below it",
        )

    def test_banner_carries_the_halted_css_hook_only_when_halted(self):
        halted_page = site.render_html(_snapshot_report({"halted": True}))
        live_page = site.render_html(_snapshot_report({"halted": False}))
        self.assertIn('class="pin halted"', halted_page)
        self.assertNotIn('class="pin halted"', live_page)
        self.assertIn('class="pin">', live_page)

    def test_missing_timestamp_omits_the_advanced_clause_without_crashing(self):
        page = site.render_html(_snapshot_report({"pinned_proposer_round_timestamp": None}))
        self.assertIn("557,840,622", page)
        self.assertNotIn("ledger last advanced", page)

    def test_unrecognised_timestamp_shape_falls_back_to_the_raw_value_without_crashing(self):
        page = site.render_html(
            _snapshot_report({"pinned_proposer_round_timestamp": "not-a-timestamp"})
        )
        self.assertIn("not-a-timestamp", page)

    def test_non_integer_state_version_does_not_crash_the_renderer(self):
        page = site.render_html(_snapshot_report({"pinned_state_version": None}))
        self.assertIn("Pinned at state version", page)

    def test_render_is_deterministic(self):
        report = _snapshot_report()
        self.assertEqual(site.render_html(report), site.render_html(report))

    def test_banner_never_invents_a_name_not_already_in_the_report(self):
        # Hard rule: the banner may state numbers/timestamps/the fixed sentences above, and
        # nothing else -- no project, person or address beyond what the report already
        # carries. This report carries none, so the banner's own text must not add any.
        page = site.render_html(_snapshot_report())
        banner = page[page.index('<section class="pin'):page.index("</section>")]
        self.assertNotIn("Radix Guild", banner)
        self.assertNotIn("http", banner)  # no gateway URL, no link, in the banner itself


GATE_SECRET_REASON = "confirmed drain path: reentrant withdraw via an unchecked callback"
GATE_SECRET_EVIDENCE = "vault_component_rdx1_holds_the_live_bug"
# The embargo block's OWN reason, not the check's -- the schema's documented example for this
# field is "describes a working fund-extraction path", every bit as sensitive as GATE_SECRET_
# REASON above, and it lives one key deeper in the same check dict (see models.redact_embargo).
EMBARGO_HOLD_REASON_TEXT = "reported upstream 2026-09-08"
THIRD_PARTY_ADDRESS = "component_rdx1" + "o" * 40
THIRD_PARTY_ID = "some-third-party-pool"
# A synthetic stand-in for a withheld third party. Deliberately not a real project's name.
THIRD_PARTY_PROJECT = "Example Pool Co"


def _gate_fixture():
    """One entity we operate (with an embargoed finding carrying a secret reason) beside
    one third-party entity (with an ordinary public finding). Exercises both halves of
    redact_for_publication at once: field-level redaction and entity-level withholding.
    """
    return {
        "schema_version": "1.0",
        "scan_id": "test-gate",
        "generated_at": "2026-09-08T00:00:00Z",
        "network": "mainnet",
        "gateway": {"url": "https://mainnet.radixdlt.com", "pinned_state_version": 1, "halted": False},
        "cohort_source": "scanner/data/cohort.json",
        "notes": ["A pre-existing cohort note that should survive gating untouched."],
        "entities": [
            {
                "id": "guild-entity",
                "project": site.OWN_PROJECT,
                "category": "guild",
                "address": "component_rdx1" + "g" * 40,
                "entity_kind": "component",
                "label": "A Guild component with a real hole in it",
                "checks": [
                    {
                        "check": "owner_role",
                        "status": "fail",
                        "severity": "critical",
                        "reason": GATE_SECRET_REASON,
                        "evidence": {"path": GATE_SECRET_EVIDENCE},
                        "embargo": {
                            "status": "embargoed",
                            "publish_at": "2026-12-01T00:00:00Z",
                            "reason": EMBARGO_HOLD_REASON_TEXT,
                        },
                        "state_version": 1,
                    },
                    {
                        "check": "metadata_claims",
                        "status": "pass",
                        "severity": "none",
                        "reason": "Metadata is complete.",
                        "evidence": {"k": "v"},
                        "embargo": {"status": "public", "publish_at": None, "reason": None},
                        "state_version": 1,
                    },
                ],
            },
            {
                "id": THIRD_PARTY_ID,
                "project": THIRD_PARTY_PROJECT,
                "category": "external",
                "address": THIRD_PARTY_ADDRESS,
                "entity_kind": "component",
                "label": "A third-party pool we do not operate",
                "checks": [
                    {
                        "check": "owner_role",
                        "status": "fail",
                        "severity": "high",
                        "reason": "This third-party finding's reason is itself entirely public.",
                        "evidence": {"k": "v"},
                        "embargo": {"status": "public", "publish_at": None, "reason": None},
                        "state_version": 1,
                    },
                ],
            },
        ],
    }


class PublicationGateTest(unittest.TestCase):
    """redact_for_publication is the one gate every published artefact passes through:
    a held check's real detail, and a third party's entire row, must both be unreachable
    from any of the three -- and the drop must be disclosed honestly, not silent."""

    def setUp(self):
        self.raw = _gate_fixture()
        self.raw_copy = json.loads(json.dumps(self.raw))  # a pristine baseline to diff against
        self.gated = site.redact_for_publication(self.raw)

    def test_does_not_mutate_its_input(self):
        self.assertEqual(self.raw, self.raw_copy)

    def test_embargoed_reason_and_evidence_absent_from_all_three_published_artefacts(self):
        page = site.render_html(self.gated)
        md = report_mod.render_markdown(self.gated)
        rendered_json = report_mod.dump_report(self.gated)
        for artefact in (page, md, rendered_json):
            self.assertNotIn(GATE_SECRET_REASON, artefact)
            self.assertNotIn(GATE_SECRET_EVIDENCE, artefact)
            # The embargo block's own `reason` is just as sensitive, and lives one key
            # deeper in the same check dict -- a naive deepcopy leaves it untouched.
            self.assertNotIn(EMBARGO_HOLD_REASON_TEXT, artefact)

    def test_held_checks_embargo_block_is_scrubbed_to_status_and_publish_at(self):
        held_check = next(
            c for c in self.gated["entities"][0]["checks"] if c["check"] == "owner_role"
        )
        embargo = held_check["embargo"]
        # Schema requires exactly these three keys (additionalProperties: false) -- `reason`
        # must stay present, just neutered, not dropped.
        self.assertEqual(set(embargo), {"status", "publish_at", "reason"})
        self.assertEqual(embargo["status"], "embargoed")
        self.assertEqual(embargo["publish_at"], "2026-12-01T00:00:00Z")
        self.assertIsNone(embargo["reason"])

    def test_a_public_checks_embargo_block_is_left_alone(self):
        public_check = next(
            c for c in self.gated["entities"][0]["checks"] if c["check"] == "metadata_claims"
        )
        self.assertEqual(
            public_check["embargo"], {"status": "public", "publish_at": None, "reason": None}
        )

    def test_render_markdown_never_leaks_a_held_reason_even_called_directly_on_the_raw_report(self):
        # cli.py's `render` subcommand can point render_markdown at an unredacted report --
        # the defense-in-depth case models.HELD_REASON exists for.
        md = report_mod.render_markdown(self.raw)
        self.assertNotIn(GATE_SECRET_REASON, md)
        self.assertNotIn(GATE_SECRET_EVIDENCE, md)

    def test_third_party_entity_never_appears_in_any_published_artefact(self):
        page = site.render_html(self.gated)
        md = report_mod.render_markdown(self.gated)
        rendered_json = report_mod.dump_report(self.gated)
        for artefact in (page, md, rendered_json):
            self.assertNotIn(THIRD_PARTY_ID, artefact)
            self.assertNotIn(THIRD_PARTY_ADDRESS, artefact)
            self.assertNotIn(THIRD_PARTY_PROJECT, artefact)

    def test_third_party_is_dropped_not_marked_held(self):
        # Not just absent from the rendered prose -- gone from the data entirely, so no
        # renderer could accidentally surface it later.
        self.assertEqual(len(self.gated["entities"]), 1)
        self.assertEqual(self.gated["entities"][0]["id"], "guild-entity")

    def test_withheld_count_is_stated_and_numerically_correct(self):
        combined_notes = " ".join(self.gated["notes"])
        self.assertIn("2 entities", combined_notes)  # 1 published + 1 withheld, scanned
        self.assertIn("1 third-party entity", combined_notes)
        # And it actually shows up on the page and in the markdown, not just the dict.
        self.assertIn("third-party", site.render_html(self.gated).lower())
        self.assertIn("third-party", report_mod.render_markdown(self.gated).lower())

    def test_withheld_projects_are_not_named_in_the_disclosure(self):
        combined_notes = " ".join(self.gated["notes"])
        self.assertNotIn(THIRD_PARTY_PROJECT, combined_notes)

    def test_published_entity_and_its_public_check_still_appear(self):
        page = site.render_html(self.gated)
        self.assertIn("component_rdx1" + "g" * 40, page)
        self.assertIn("Metadata is complete.", page)

    def test_finding_existence_status_and_severity_still_publish_for_a_held_check(self):
        page = site.render_html(self.gated)
        self.assertIn("FAIL", page)
        self.assertIn("critical", page)
        self.assertIn("2026-12-01T00:00:00Z", page)


NOTE_NAMING_THIRD_PARTY = (
    f"A scoping note named {THIRD_PARTY_ID}, the {THIRD_PARTY_PROJECT} pool at "
    f"{THIRD_PARTY_ADDRESS}, as a candidate before the final list settled."
)


def _gate_fixture_with_named_note():
    """The same fixture as `_gate_fixture`, plus one more top-level note that names the
    withheld third party by project, id and address -- the shape the note gate exists to
    catch: a name repeated in prose below an entity gate that already withheld it."""
    fixture = _gate_fixture()
    fixture["notes"] = list(fixture["notes"]) + [NOTE_NAMING_THIRD_PARTY]
    return fixture


class NoteGateTest(unittest.TestCase):
    """The top-level `notes` array is not exempt from the publication gate: a note that
    names a withheld third party undoes the entity-level withholding beside it."""

    def setUp(self):
        self.raw = _gate_fixture_with_named_note()
        self.gated = site.redact_for_publication(self.raw)

    def test_note_naming_a_withheld_entity_is_dropped(self):
        combined = " ".join(self.gated["notes"])
        self.assertNotIn(THIRD_PARTY_PROJECT, combined)
        self.assertNotIn(THIRD_PARTY_ID, combined)
        self.assertNotIn(THIRD_PARTY_ADDRESS, combined)

    def test_a_note_naming_nothing_withheld_survives_untouched(self):
        combined = " ".join(self.gated["notes"])
        self.assertIn("A pre-existing cohort note that should survive gating untouched.", combined)

    def test_the_drop_is_disclosed_not_silent(self):
        combined = " ".join(self.gated["notes"])
        self.assertIn("1 cohort note", combined)

    def test_dropped_note_is_absent_from_every_rendered_artefact(self):
        page = site.render_html(self.gated)
        md = report_mod.render_markdown(self.gated)
        rendered_json = report_mod.dump_report(self.gated)
        for artefact in (page, md, rendered_json):
            self.assertNotIn(THIRD_PARTY_PROJECT, artefact)
            self.assertNotIn(THIRD_PARTY_ID, artefact)
            self.assertNotIn(THIRD_PARTY_ADDRESS, artefact)

    def test_matching_is_case_insensitive(self):
        fixture = _gate_fixture()
        fixture["notes"] = list(fixture["notes"]) + [
            f"a note that mentions {THIRD_PARTY_PROJECT.lower()} in lowercase"
        ]
        gated = site.redact_for_publication(fixture)
        combined = " ".join(gated["notes"])
        self.assertNotIn(f"mentions {THIRD_PARTY_PROJECT.lower()} in lowercase", combined)

    def test_idempotent_second_gating_pass_adds_nothing_further(self):
        # redact_for_publication(gated) must equal gated -- build() relies on this to re-gate
        # an already-public dated file in place without double-counting on every --sync.
        self.assertEqual(self.gated, site.redact_for_publication(self.gated))


NEVER_SCANNED_THIRD_PARTY = "Never Scanned Co"
# Starts with "The", which the allow-list clears, so ONLY the unlisted name can trip the screen.
NOTE_NAMING_A_NEVER_SCANNED_THIRD_PARTY = (
    f"The earlier scoping pass considered {NEVER_SCANNED_THIRD_PARTY} for this cohort before "
    "a substitute was chosen; it was never added as a scanned entity."
)


class NeverScannedThirdPartyNoteTest(unittest.TestCase):
    """The real gap the old entity-scoped note filter had, proven directly: a project named
    only in a cohort note's prose -- never itself a scanned cohort entity, so
    `_withheld_needles` has no needle for it at all -- must still be withheld. Filtering by
    "was this entity withheld this run" is the wrong question; `_note_is_safe`'s allow-list is
    what actually closes this."""

    def setUp(self):
        self.raw = _gate_fixture()
        self.raw["notes"] = list(self.raw["notes"]) + [NOTE_NAMING_A_NEVER_SCANNED_THIRD_PARTY]
        # Confirm the fixture actually tests what it claims to: the named project must not be
        # any entity in this report at all, scanned or withheld -- otherwise this test would
        # pass for the OLD (entity-scoped) reason instead of the new one.
        named_projects = {e["project"] for e in self.raw["entities"]}
        assert NEVER_SCANNED_THIRD_PARTY not in named_projects
        self.gated = site.redact_for_publication(self.raw)

    def test_note_naming_a_project_that_was_never_a_scanned_entity_is_still_dropped(self):
        combined = " ".join(self.gated["notes"])
        self.assertNotIn(NEVER_SCANNED_THIRD_PARTY, combined)

    def test_the_drop_is_disclosed_not_silent(self):
        combined = " ".join(self.gated["notes"])
        self.assertIn("1 cohort note", combined)

    def test_dropped_note_is_absent_from_every_rendered_artefact(self):
        page = site.render_html(self.gated)
        md = report_mod.render_markdown(self.gated)
        rendered_json = report_mod.dump_report(self.gated)
        for artefact in (page, md, rendered_json):
            self.assertNotIn(NEVER_SCANNED_THIRD_PARTY, artefact)


NAME_SCREEN_THIRD_PARTY_MENTION = f"This finding also cross-references {THIRD_PARTY_PROJECT}'s own pool."


def _gate_fixture_with_name_screen_check():
    """The same fixture as `_gate_fixture`, but the PUBLISHED (Guild) entity's public check
    carries a `reason` that names the withheld third party -- the shape Gateway-sourced free
    text on our own entity's own finding could take (see redact_for_publication's rule 4)."""
    fixture = _gate_fixture()
    metadata_check = next(
        c for c in fixture["entities"][0]["checks"] if c["check"] == "metadata_claims"
    )
    metadata_check["reason"] = NAME_SCREEN_THIRD_PARTY_MENTION
    metadata_check["evidence"] = {"k": "v", "claimed_partner": THIRD_PARTY_ADDRESS}
    return fixture


class PublishedEntityCheckTextNameScreenTest(unittest.TestCase):
    """Rule 4: a PUBLISHED entity's own check can still leak a withheld third party's name
    through free text -- `reason`, or a Gateway-sourced value inside `evidence` -- even though
    the check itself is public and belongs to us. Field-level rule 1 doesn't apply (this check
    was never embargoed); rule 4 exists specifically for this shape."""

    def setUp(self):
        self.raw = _gate_fixture_with_name_screen_check()
        self.gated = site.redact_for_publication(self.raw)

    def _published_metadata_check(self, report):
        entity = next(e for e in report["entities"] if e["id"] == "guild-entity")
        return next(c for c in entity["checks"] if c["check"] == "metadata_claims")

    def test_reason_naming_a_withheld_third_party_is_screened(self):
        check = self._published_metadata_check(self.gated)
        self.assertNotIn(THIRD_PARTY_PROJECT, check["reason"])
        self.assertEqual(check["reason"], models.NAME_SCREEN_REASON)

    def test_evidence_naming_a_withheld_third_party_is_screened(self):
        check = self._published_metadata_check(self.gated)
        self.assertNotIn(THIRD_PARTY_ADDRESS, str(check["evidence"]))
        self.assertEqual(check["evidence"], models.NAME_SCREEN_EVIDENCE)

    def test_check_status_and_severity_are_unaffected(self):
        # Only the free text is screened -- this check was never embargoed, and the name
        # screen must not quietly turn it into something that reads as held.
        check = self._published_metadata_check(self.gated)
        self.assertEqual(check["status"], "pass")
        self.assertEqual(check["severity"], "none")
        self.assertEqual(check["embargo"], {"status": "public", "publish_at": None, "reason": None})

    def test_screened_text_absent_from_every_rendered_artefact(self):
        page = site.render_html(self.gated)
        md = report_mod.render_markdown(self.gated)
        rendered_json = report_mod.dump_report(self.gated)
        for artefact in (page, md, rendered_json):
            self.assertNotIn(THIRD_PARTY_PROJECT, artefact)
            self.assertNotIn(THIRD_PARTY_ADDRESS, artefact)

    def test_the_screen_is_disclosed_not_silent(self):
        combined = " ".join(self.gated["notes"])
        self.assertIn("1 check finding", combined)

    def test_a_public_check_with_no_third_party_reference_is_left_alone(self):
        # The OTHER public check on the same entity (owner_role's real fail is embargoed in
        # this fixture, so use the metadata check's sibling instead) must not be touched just
        # because a needle exists this run.
        untouched = _gate_fixture()
        gated = site.redact_for_publication(untouched)
        check = next(
            c for c in gated["entities"][0]["checks"] if c["check"] == "metadata_claims"
        )
        self.assertEqual(check["reason"], "Metadata is complete.")


class BuildGatesSyntheticResultsDirTest(unittest.TestCase):
    """build()'s gating of the dated source path and latest.json is otherwise untestable
    against the real committed fixture: that fixture is already at the gate's fixed point
    (3 all-public Radix Guild entities, zero embargoed checks), so a build() that quietly
    fell back to raw bytes for either path would still pass every other test in this file.
    This seeds a synthetic results_dir carrying an embargoed check, a third-party entity
    AND a note naming that third party all at once, so a fallback to raw anywhere is
    guaranteed to leave a secret string sitting in the output.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.raw = _gate_fixture_with_named_note()
        self.dated_path = os.path.join(self.tmpdir, "2026-09-08.json")
        with open(self.dated_path, "w", encoding="utf-8") as fh:
            fh.write(report_mod.dump_report(self.raw))
        self.page_path = os.path.join(self.tmpdir, "index.html")
        self.latest_json_path = os.path.join(self.tmpdir, "latest.json")

    def test_dated_source_and_latest_json_equal_the_gated_form_not_raw_bytes(self):
        expected = report_mod.dump_report(site.redact_for_publication(self.raw))
        result = site.build(results_dir=self.tmpdir, page_path=self.page_path)
        self.assertEqual(result[self.dated_path], expected)
        self.assertEqual(result[self.latest_json_path], expected)

    def test_no_secret_survives_in_any_of_the_four_outputs(self):
        result = site.build(results_dir=self.tmpdir, page_path=self.page_path)
        self.assertEqual(len(result), 4)
        for content in result.values():
            self.assertNotIn(GATE_SECRET_REASON, content)
            self.assertNotIn(GATE_SECRET_EVIDENCE, content)
            self.assertNotIn(EMBARGO_HOLD_REASON_TEXT, content)
            self.assertNotIn(THIRD_PARTY_PROJECT, content)
            self.assertNotIn(THIRD_PARTY_ID, content)
            self.assertNotIn(THIRD_PARTY_ADDRESS, content)


class SyncTest(unittest.TestCase):
    """A stale page is worse than no page: CI catches drift, not the reader."""

    def test_committed_artefacts_match_the_newest_report(self):
        for path, content in site.build(RESULTS, PAGE).items():
            self.assertTrue(os.path.exists(path), f"{path} is missing — run `make scan-page`")
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(
                    handle.read(),
                    content,
                    f"{os.path.relpath(path, ROOT)} is stale — run `make scan-page`",
                )

    def test_latest_json_is_byte_identical_to_the_newest_dated_report(self):
        with open(site.newest_dated_report(RESULTS), encoding="utf-8") as handle:
            newest = handle.read()
        with open(os.path.join(RESULTS, "latest.json"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), newest)

    def test_check_exits_clean_when_the_tree_is_synced(self):
        # build() now gates and returns the dated source file itself, not just latest.json/.md
        # and the page (see build()'s docstring) -- this proves --check still round-trips
        # cleanly against that fourth path, not only the three it always managed.
        self.assertEqual(site.main(["scanner.site", "--check"]), 0)

    def test_committed_dated_report_is_itself_gated(self):
        # The dated report is committed and served raw from GitHub same as latest.json -- it
        # must never be the pre-gate original (see the module docstring's property 4).
        with open(site.newest_dated_report(RESULTS), encoding="utf-8") as handle:
            committed = json.load(handle)
        self.assertEqual(committed, site.redact_for_publication(committed))


class PublisherAcknowledgementTest(unittest.TestCase):
    """The page says plainly who it covers and who fails -- from the report, never beyond it.

    Regression for a lede that claimed the publisher's own entities "fail alongside everyone
    else's": the published scans list only the publisher's own rows and withhold every third
    party (see redact_for_publication), so nobody else's failures were ever on the page.
    """

    def setUp(self):
        with open(site.newest_dated_report(RESULTS), encoding="utf-8") as handle:
            self.report = json.load(handle)
        self.page = site.render_html(self.report)

    def test_lede_does_not_claim_third_party_failures_are_published(self):
        self.assertNotIn("everyone else", self.page)
        self.assertNotIn("alongside", self.page)

    def test_lede_says_the_page_covers_only_the_publishers_own_entities(self):
        self.assertIn("covers only the entities Radix Guild operates itself", self.page)
        self.assertIn("Third-party projects are not listed, scored or named here", self.page)

    def test_failing_own_entities_are_named_and_acknowledged(self):
        failing = [
            e["label"] for e in self.report["entities"]
            if any(c["status"] == "fail" for c in e["checks"])
        ]
        self.assertTrue(failing, "the committed report should carry failing entities")
        self.assertIn(
            f"{len(failing)} of {len(self.report['entities'])} published entities have a failing check",
            self.page,
        )
        for label in failing:
            self.assertIn(label, self.page)
        self.assertIn("All are entities Radix Guild operates itself", self.page)
        self.assertIn("not exempted, reclassified or hidden", self.page)

    def test_no_acknowledgement_when_nothing_fails(self):
        clean = json.loads(json.dumps(self.report))
        for entity in clean["entities"]:
            for check in entity["checks"]:
                if check["status"] == "fail":
                    check["status"] = "pass"
                    check["severity"] = "none"
        page = site.render_html(clean)
        self.assertNotIn("have a failing check", page)

    def test_a_failing_third_party_row_is_not_described_as_the_publishers_own(self):
        # render_html is a pure projection; if an ungated report reaches it, the acknowledgement
        # must not attribute someone else's failure to the publisher.
        page = site.render_html(_embargoed_report())
        self.assertIn("have a failing check", page)
        self.assertNotIn("All are entities Radix Guild operates itself", page)

    def test_banner_does_not_promise_a_rescan(self):
        for halted in (True, False):
            with self.subTest(halted=halted):
                page = site.render_html(_snapshot_report({"halted": halted}))
                self.assertNotIn("when the ledger moves", page)
                self.assertIn("not refreshed automatically", page)


if __name__ == "__main__":
    unittest.main()
