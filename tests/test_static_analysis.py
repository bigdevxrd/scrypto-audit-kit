"""Unit tests for bin/static_analysis.py — deterministic, no API."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import static_analysis as sa  # noqa: E402

PKG = os.path.join(ROOT, "examples", "vulnerable-vault")


def fired(src):
    """Set of (rule, line) the analyzer reports for a snippet."""
    return {(f["rule"], f["line"]) for f in sa.analyze_text("t.rs", src)}


class TestFixture(unittest.TestCase):
    """The planted-bug fixture is the analyzer's golden oracle."""

    @classmethod
    def setUpClass(cls):
        cls.findings = sa.analyze_package(PKG)

    def test_exactly_three_findings(self):
        self.assertEqual(len(self.findings), 3)

    def test_rules_and_locations(self):
        got = {(f["rule"], f["location"]) for f in self.findings}
        self.assertEqual(got, {
            ("self-updatable-role", "src/lib.rs:23"),
            ("owner-role-none", "src/lib.rs:72"),
            ("unbounded-take-all", "src/lib.rs:120"),
        })

    def test_schema_shape(self):
        for f in self.findings:
            self.assertTrue(f["id"].startswith("S-"))
            self.assertEqual(f["source"], "static")
            self.assertEqual(f["confidence"], "high")
            self.assertIn(f["severity"], sa.sak_lib.SEV_RANK)
            self.assertTrue(f["suggested_direction"])

    def test_ids_sequential(self):
        self.assertEqual([f["id"] for f in self.findings], ["S-001", "S-002", "S-003"])

    def test_no_false_positives(self):
        # the fixture has enable_method_auth!, no floats/addresses/panics/unsafe
        rules = {f["rule"] for f in self.findings}
        for absent in ("float-usage", "hardcoded-address", "missing-method-auth",
                       "panic-macro", "unsafe-block", "todo-comment"):
            self.assertNotIn(absent, rules)


class TestPrecision(unittest.TestCase):
    def test_comment_does_not_fire(self):
        self.assertEqual(fired("// calls self.vault.take_all() and OwnerRole::None\nfn f() {}"), set())

    def test_string_does_not_fire(self):
        self.assertEqual(fired('fn f() { let s = "take_all() OwnerRole::None"; }'), set())

    def test_block_comment_does_not_fire(self):
        self.assertEqual(fired("/* self.vault.take_all() */\nfn f() {}"), set())

    def test_real_code_fires(self):
        self.assertIn(("unbounded-take-all", 1), fired("self.vault.take_all();"))

    def test_self_updatable_precision(self):
        self.assertEqual(fired("admin => updatable_by: [owner];"), set())            # different role: clean
        self.assertIn(("self-updatable-role", 1), fired("admin => updatable_by: [admin];"))

    def test_float_usage_fires(self):
        self.assertIn(("float-usage", 1), fired("let x: f64 = compute();"))

    def test_missing_method_auth(self):
        blueprint = "#[blueprint]\nmod m {\n  impl X { pub fn f(&mut self) {} }\n}"
        self.assertIn("missing-method-auth", {r for r, _ in fired(blueprint)})
        with_macro = "#[blueprint]\nmod m {\n  enable_method_auth! {}\n  impl X { pub fn f(&mut self) {} }\n}"
        self.assertNotIn("missing-method-auth", {r for r, _ in fired(with_macro)})

    def test_clean_snippet_is_silent(self):
        self.assertEqual(fired("fn add(a: Decimal, b: Decimal) -> Decimal { a + b }"), set())


class TestSuppression(unittest.TestCase):
    def test_inline_suppress(self):
        self.assertEqual(fired("self.vault.take_all(); // sak:allow unbounded-take-all"), set())

    def test_suppress_on_line_above(self):
        self.assertEqual(fired("// sak:allow unbounded-take-all\nself.vault.take_all();"), set())

    def test_suppress_all(self):
        self.assertEqual(fired("self.vault.take_all(); // sak:allow all"), set())

    def test_suppress_wrong_rule_still_fires(self):
        self.assertIn(("unbounded-take-all", 1), fired("self.vault.take_all(); // sak:allow float-usage"))


class TestStripper(unittest.TestCase):
    def test_preserves_line_count(self):
        src = 'a\n// b\n"c\nd"\ne\n'
        self.assertEqual(sa.strip_comments_and_strings(src).count("\n"), src.count("\n"))

    def test_raw_string_blanked(self):
        out = sa.strip_comments_and_strings('let s = r#"take_all()"#;')
        self.assertNotIn("take_all", out)

    def test_lifetime_not_treated_as_char(self):
        # &'a self must survive (no spurious char-literal swallowing the rest of the line)
        out = sa.strip_comments_and_strings("fn f<'a>(&'a self) { take_all() }")
        self.assertIn("take_all", out)


class TestEvasionsFixed(unittest.TestCase):
    """Regression tests for the evasions/bugs the adversarial pass found (R3)."""

    def test_string_continuation_preserves_line_numbers(self):
        # "x\<newline>y" is one string spanning two lines; take_all must report on line 3
        src = 'let s = "x\\\ny";\nself.vault.take_all();'
        self.assertIn(("unbounded-take-all", 3), fired(src))

    def test_nested_block_comment_no_leak(self):
        self.assertEqual(fired("/* a /* b */ self.vault.take_all(); */\nfn f(){}"), set())

    def test_suppression_inside_string_does_not_suppress(self):
        src = 'let doc = "// sak:allow unbounded-take-all";\nself.vault.take_all();'
        self.assertIn(("unbounded-take-all", 2), fired(src))

    def test_qualified_blueprint_path_caught(self):
        bp = "#[scrypto::blueprint]\nmod m {\n  impl X { pub fn f(&mut self) {} }\n}"
        self.assertIn("missing-method-auth", {r for r, _ in fired(bp)})

    def test_ownerrole_none_multiline_caught(self):
        # rustfmt puts the arg on its own line — must not evade
        self.assertIn("owner-role-none",
                      {r for r, _ in fired("let g = b.prepare_to_globalize(\n    OwnerRole::None,\n);")})

    def test_take_all_multiline_caught(self):
        self.assertIn("unbounded-take-all", {r for r, _ in fired("self.vault.take_all(\n)")})

    def test_hardcoded_address_broadened(self):
        addr = "pool_rdx1qcdefghjkmnpqrstuvwxyz23456789"
        self.assertIn("hardcoded-address", {r for r, _ in fired(f'let a = "{addr}";')})

    def test_hardcoded_address_not_in_comment(self):
        self.assertEqual(fired("// see pool_rdx1qcdefghjkmnpqrstuvwxyz23456789"), set())


if __name__ == "__main__":
    unittest.main()
