"""Unit tests for scanner/models.py -- the status/severity contract every check must honor."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanner import models  # noqa: E402


class TestMakeFindingContract(unittest.TestCase):
    def test_pass_none_is_valid(self):
        f = models.make_finding("owner_role", "pass", "none", "ok", {"x": 1}, 123)
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["severity"], "none")
        self.assertEqual(f["state_version"], 123)
        self.assertEqual(f["embargo"], {"status": "public", "publish_at": None, "reason": None})

    def test_not_applicable_must_be_none_severity(self):
        models.make_finding("resource_authority", "not_applicable", "none", "n/a", {"x": 1}, 1)
        with self.assertRaises(models.CheckContractError):
            models.make_finding("resource_authority", "not_applicable", "informational", "n/a", {"x": 1}, 1)

    def test_informational_cannot_carry_high_or_critical(self):
        # This is the load-bearing rule: a check that cannot determine intent must return
        # informational, and informational must never smuggle in a red severity.
        for bad in ("high", "critical"):
            with self.assertRaises(models.CheckContractError):
                models.make_finding("owner_role", "informational", bad, "ambiguous", {"x": 1}, 1)
        for ok in ("informational", "low", "medium"):
            models.make_finding("owner_role", "informational", ok, "ambiguous", {"x": 1}, 1)

    def test_fail_cannot_carry_none_severity(self):
        with self.assertRaises(models.CheckContractError):
            models.make_finding("owner_role", "fail", "none", "bad", {"x": 1}, 1)

    def test_unknown_check_name_rejected(self):
        with self.assertRaises(models.CheckContractError):
            models.make_finding("not_a_real_check", "pass", "none", "ok", {"x": 1}, 1)

    def test_unknown_status_rejected(self):
        with self.assertRaises(models.CheckContractError):
            models.make_finding("owner_role", "maybe", "none", "ok", {"x": 1}, 1)

    def test_empty_reason_rejected(self):
        with self.assertRaises(models.CheckContractError):
            models.make_finding("owner_role", "pass", "none", "   ", {"x": 1}, 1)

    def test_empty_evidence_rejected(self):
        with self.assertRaises(models.CheckContractError):
            models.make_finding("owner_role", "pass", "none", "ok", {}, 1)
        with self.assertRaises(models.CheckContractError):
            models.make_finding("owner_role", "pass", "none", "ok", "not-a-dict", 1)

    def test_embargo_override_is_used_verbatim(self):
        embargo = models.embargoed("discloses a drain path", "2026-12-09T00:00:00Z")
        f = models.make_finding("owner_role", "fail", "critical", "bad", {"x": 1}, 1, embargo=embargo)
        self.assertEqual(f["embargo"]["status"], "embargoed")
        self.assertEqual(f["embargo"]["publish_at"], "2026-12-09T00:00:00Z")


class TestEmbargoHelpers(unittest.TestCase):
    def test_public_embargo_shape(self):
        self.assertEqual(models.public_embargo(), {"status": "public", "publish_at": None, "reason": None})

    def test_embargoed_requires_both_fields(self):
        with self.assertRaises(models.CheckContractError):
            models.embargoed("", "2026-01-01T00:00:00Z")
        with self.assertRaises(models.CheckContractError):
            models.embargoed("some reason", "")

    def test_embargoed_shape(self):
        e = models.embargoed("some reason", "2026-01-01T00:00:00Z")
        self.assertEqual(e, {"status": "embargoed", "publish_at": "2026-01-01T00:00:00Z", "reason": "some reason"})


class TestIsPublicFailsClosed(unittest.TestCase):
    """A check missing its embargo block entirely, or carrying a malformed one, must read as
    held, never public -- the only safe default for a field that gates a finding's disclosure."""

    def test_missing_embargo_key_is_not_public(self):
        self.assertFalse(models.is_public({"check": "owner_role"}))

    def test_none_embargo_is_not_public(self):
        self.assertFalse(models.is_public({"embargo": None}))

    def test_non_dict_embargo_is_not_public(self):
        self.assertFalse(models.is_public({"embargo": "not a dict"}))
        self.assertFalse(models.is_public({"embargo": ["also not a dict"]}))


class TestRedactEmbargoFailsClosed(unittest.TestCase):
    """redact_embargo's own docstring: a non-dict/malformed embargo must redact to an
    all-held placeholder instead of raising or passing anything through -- a check
    missing/mangling its own embargo block is the last place a real reason should leak
    through by accident. This isinstance branch had no test before this one.
    """

    def test_none_embargo_redacts_to_the_all_held_placeholder(self):
        self.assertEqual(
            models.redact_embargo(None),
            {"status": "embargoed", "publish_at": None, "reason": None},
        )

    def test_bare_string_embargo_redacts_to_the_all_held_placeholder(self):
        self.assertEqual(
            models.redact_embargo("not a dict"),
            {"status": "embargoed", "publish_at": None, "reason": None},
        )

    def test_non_empty_list_embargo_redacts_to_the_all_held_placeholder(self):
        self.assertEqual(
            models.redact_embargo(["also not a dict"]),
            {"status": "embargoed", "publish_at": None, "reason": None},
        )

    def test_a_malformed_embargo_never_leaks_its_own_reason_through(self):
        # A dict-shaped-but-wrong embargo (missing status/publish_at) is the OTHER branch
        # (not this one) -- covered by test_scanner_site's held-embargo tests. This class is
        # specifically about the non-dict, isinstance-guarded fail-closed path.
        redacted = models.redact_embargo("describes a working fund-extraction path")
        self.assertIsNone(redacted["reason"])
        self.assertNotIn("fund-extraction", str(redacted))


class TestUtcNowIso(unittest.TestCase):
    def test_format(self):
        ts = models.utcnow_iso()
        self.assertTrue(ts.endswith("Z"))
        self.assertEqual(len(ts), len("2026-09-08T09:15:00Z"))


if __name__ == "__main__":
    unittest.main()
