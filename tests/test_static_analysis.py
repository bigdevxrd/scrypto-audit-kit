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

    def test_finding_count(self):
        self.assertEqual(len(self.findings), 5)

    def test_rules_and_locations(self):
        got = {(f["rule"], f["location"]) for f in self.findings}
        self.assertEqual(got, {
            ("self-updatable-role", "src/lib.rs:23"),
            ("owner-role-none", "src/lib.rs:72"),
            ("raw-decimal-arith", "src/lib.rs:86"),
            ("raw-decimal-arith", "src/lib.rs:98"),
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
        self.assertEqual([f["id"] for f in self.findings], ["S-001", "S-002", "S-003", "S-004", "S-005"])

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

    def test_suppress_all_is_rejected(self):
        # blanket `sak:allow all` must NOT zero findings — the auditee could hide everything.
        self.assertIn(("unbounded-take-all", 1), fired("self.vault.take_all(); // sak:allow all"))

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


class TestNewRules(unittest.TestCase):
    """The high-value rules added after the adversarial pass (R4), kept high-precision."""

    def test_raw_decimal_arith_on_amount(self):
        self.assertIn("raw-decimal-arith", {r for r, _ in fired("let v = self.vault.amount() * price;")})

    def test_raw_decimal_arith_on_dec_div(self):
        self.assertIn("raw-decimal-arith", {r for r, _ in fired("let h = x / dec!(2);")})

    def test_plain_addition_is_clean(self):
        self.assertEqual(fired("fn f(a: Decimal, b: Decimal) -> Decimal { a + b }"), set())

    def test_unwrap_expect_fires(self):
        self.assertIn(("unwrap-expect", 1), fired("let x = thing.unwrap();"))
        self.assertIn(("unwrap-expect", 1), fired('let x = thing.expect("msg");'))

    def test_public_mint_burn_fires(self):
        self.assertIn("public-mint-burn", {r for r, _ in fired("pub fn mint(&mut self) {}")})
        self.assertIn("public-mint-burn", {r for r, _ in fired("pub fn burn_tokens(&mut self) {}")})

    def test_attestation_blueprint_only_fixed_owner(self):
        # Dogfood: the kit's own L3 blueprint carries exactly one static finding — owner-role-fixed
        # (low) at attestation/src/lib.rs:130, where prepare_to_globalize pins the owner rule.
        # It is a true positive and it is left unwaived: the registry's *record* is deliberately
        # immutable (soulbound, no burn), but its *administration* is not — the OWNER can already
        # re-point `issuer`, so Fixed only removes the path to re-point the OWNER rule itself.
        # attestation/README.md publishes this finding instead of a "0 findings" claim; if that
        # design decision is ever revisited, change the blueprint and this assertion together.
        findings = sa.analyze_package(os.path.join(ROOT, "attestation"))
        self.assertEqual([(f["rule"], f["severity"]) for f in findings], [("owner-role-fixed", "low")])


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

    def test_take_all_newline_before_paren_caught(self):
        # the evasion the review found: newline BETWEEN take_all and its ( — line scan missed it
        self.assertIn("unbounded-take-all", {r for r, _ in fired("self.vault.take_all\n();")})

    def test_take_amount_full_drain_caught(self):
        self.assertIn("unbounded-take-all", {r for r, _ in fired("let b = self.vault.take(self.vault.amount());")})

    def test_unsafe_newline_split_caught(self):
        self.assertIn("unsafe-block", {r for r, _ in fired("unsafe\n{ ptr::read(p) }")})

    def test_public_mint_newline_split_caught(self):
        self.assertIn("public-mint-burn", {r for r, _ in fired("pub\nfn mint_free(&mut self) {}")})

    def test_self_updatable_role_wrapped_list_caught(self):
        self.assertIn("self-updatable-role", {r for r, _ in fired("admin => updatable_by: [\n    admin\n];")})

    def test_suffixed_float_literal_caught(self):
        self.assertIn("float-usage", {r for r, _ in fired("let slippage = 0.05f64;")})
        self.assertIn("float-usage", {r for r, _ in fired("let n = 3f32;")})

    def test_float_not_matched_inside_identifier(self):
        # a broadened float rule must not fire on identifiers that merely contain f64/f32
        self.assertEqual(fired("let buffer2f64_len = compute();"), set())

    def test_hardcoded_address_broadened(self):
        addr = "pool_rdx1qcdefghjkmnpqrstuvwxyz23456789"
        self.assertIn("hardcoded-address", {r for r, _ in fired(f'let a = "{addr}";')})

    def test_hardcoded_address_not_in_comment(self):
        self.assertEqual(fired("// see pool_rdx1qcdefghjkmnpqrstuvwxyz23456789"), set())

    def test_hand_rolled_address_check_raw_string_caught(self):
        # the pattern anchored on a literal `"`, so a raw string slipped past this rule while the
        # sibling hardcoded-address still matched inside one — the stripper keeps raw-string
        # contents under keep_strings, so this was a rule inconsistency, not a stripper limit.
        self.assertIn("hand-rolled-address-check",
                      {r for r, _ in fired('if a.starts_with(r#"account_rdx1"#) { ok() }')})
        self.assertIn("hand-rolled-address-check",
                      {r for r, _ in fired('if a.starts_with(r"account_rdx1") { ok() }')})


class TestBugHunt20260718(unittest.TestCase):
    """Regression tests for the 2026-07-18 bug-hunt findings (H1, H2, M3, L1, L3)."""

    def test_raw_decimal_arith_rustfmt_wrapped_caught(self):
        # H1: rustfmt wraps a long Decimal expression across two lines, operator leading the
        # continuation line — the per-line regex saw neither operand+operator on any single line.
        src = "let v = self.vault.amount()\n    * self.oracle.price;"
        self.assertIn("raw-decimal-arith", {r for r, _ in fired(src)})

    def test_raw_decimal_arith_rustfmt_wrapped_div_caught(self):
        src = "let h = x\n    / dec!(2);"
        self.assertIn("raw-decimal-arith", {r for r, _ in fired(src)})

    def test_missing_method_auth_scoped_per_blueprint(self):
        # H2: one blueprint carries enable_method_auth!, a second in the SAME file does not —
        # the old whole-file check ("does the macro appear anywhere") let the first blueprint's
        # macro vouch for the second blueprint's missing auth too. Must scope to each blueprint.
        src = """#[blueprint]
mod a {
  enable_method_auth!{ methods { f => PUBLIC; } }
  struct A {}
  impl A { pub fn f(&self) {} }
}
#[blueprint]
mod b {
  struct B {}
  impl B { pub fn drain(&mut self) {} }
}
"""
        findings = fired(src)
        auth_findings = [ln for r, ln in findings if r == "missing-method-auth"]
        self.assertEqual(auth_findings, [7])  # only the second `#[blueprint]`, not the first

    def test_missing_method_auth_both_blueprints_unauthed(self):
        # both blueprints lacking the macro must each get their own finding, not just one.
        src = ("#[blueprint]\nmod a {\n  impl A { pub fn f(&self) {} }\n}\n"
               "#[blueprint]\nmod b {\n  impl B { pub fn g(&self) {} }\n}\n")
        auth_findings = sorted(ln for r, ln in fired(src) if r == "missing-method-auth")
        self.assertEqual(auth_findings, [1, 5])

    def test_inline_suppress_does_not_leak_to_next_line(self):
        # M3: an inline `// sak:allow` trailing line N's code was also silently suppressing a
        # genuine, unrelated finding on line N+1 (whose "line above" happens to be line N, and
        # the old check didn't require that "line above" to be a dedicated comment-only line).
        src = "self.vault.take_all(); // sak:allow unbounded-take-all\nself.vault.take_all();"
        self.assertEqual(fired(src), {("unbounded-take-all", 2)})

    def test_standalone_suppress_comment_still_covers_next_line(self):
        # the legitimate "line above" form — a dedicated comment line with no code of its own —
        # must keep working.
        src = "// sak:allow unbounded-take-all\nself.vault.take_all();\nself.vault.take_all();"
        self.assertEqual(fired(src), {("unbounded-take-all", 3)})

    def test_unsafe_fn_caught(self):
        # L1: only `unsafe { ... }` fired; `unsafe fn` / `unsafe impl` did not, though the same
        # "sidesteps the safety guarantees" rationale applies to both.
        self.assertIn(("unsafe-block", 1), fired("pub unsafe fn raw(&self) {}"))

    def test_unsafe_impl_caught(self):
        self.assertIn(("unsafe-block", 1), fired("unsafe impl Send for V {}"))

    def test_float_exponent_form_caught(self):
        # L3: the numeric-literal-suffix branch had no exponent group, so `1e5f64` fell through
        # both alternatives (the plain-suffix one requires `f32/64` directly after the digits).
        self.assertIn(("float-usage", 1), fired("let x = 1e5f64;"))
        self.assertIn(("float-usage", 1), fired("let y = 1.5e3f32;"))


class TestPublicMintBurnConsultsAuthBlock(unittest.TestCase):
    """public-mint-burn must read enable_method_auth! before it fires.

    The rule matched `pub fn \\w*(mint|burn)\\w*` and never looked at the auth block, so a
    method the SAME file declares `restrict_to: [...]` was reported as an unrestricted mint.
    That is what it did to a live mainnet component (scrypto-xrd wallet-manager), whose
    `mint_manager_badge => restrict_to: [admin, OWNER];` sits a few lines above the struct.
    """

    # The shape of the real blueprint, trimmed: a roles block, an interleaved comment, and a
    # methods block declaring one PUBLIC read and one restricted mint.
    RESTRICTED = """#[blueprint]
mod wallet_manager {
    enable_method_auth! {
        roles {
            admin => updatable_by: [OWNER];
        },
        methods {
            // Public reads
            get_badge_info => PUBLIC;
            // Admin/owner only
            mint_manager_badge => restrict_to: [admin, OWNER];
        }
    }
    struct WalletManager {}
    impl WalletManager {
        pub fn get_badge_info(&self) {}
        pub fn mint_manager_badge(&mut self, name: String) -> Bucket {}
    }
}
"""

    def test_restricted_mint_does_not_fire(self):
        self.assertNotIn("public-mint-burn", {r for r, _ in fired(self.RESTRICTED)})

    def test_public_mint_still_fires(self):
        src = self.RESTRICTED.replace("restrict_to: [admin, OWNER]", "PUBLIC")
        self.assertIn("public-mint-burn", {r for r, _ in fired(src)})

    def test_restricted_burn_does_not_fire(self):
        src = self.RESTRICTED.replace("mint_manager_badge", "burn_manager_badge")
        self.assertNotIn("public-mint-burn", {r for r, _ in fired(src)})

    def test_wrapped_restrict_list_still_suppresses(self):
        # rustfmt puts a long role list on its own lines — the suppression must survive that
        wrapped = "restrict_to: [\n                admin,\n                OWNER,\n            ]"
        src = self.RESTRICTED.replace("restrict_to: [admin, OWNER]", wrapped)
        self.assertNotIn("public-mint-burn", {r for r, _ in fired(src)})

    def test_method_absent_from_macro_still_fires(self):
        # the macro exists but says nothing about this method — no evidence of a gate, so fire
        src = self.RESTRICTED.replace("            mint_manager_badge => restrict_to: [admin, OWNER];\n", "")
        self.assertIn("public-mint-burn", {r for r, _ in fired(src)})

    def test_roles_block_entries_are_not_read_as_methods(self):
        # `roles { ... }` uses the same `name => ...;` shape as `methods { ... }`, so parsing the
        # whole macro would register every role as a method. Asserted on the parser directly:
        # the behavioural symptom needs a role and a method to collide by name, which valid
        # Scrypto makes hard to construct, but the map itself must stay clean either way.
        st = sa.strip_comments_and_strings(self.RESTRICTED)
        (_start, _end, decls), = sa._method_auth_index(st)
        self.assertEqual(sorted(decls), ["get_badge_info", "mint_manager_badge"])
        self.assertEqual(decls["mint_manager_badge"], "restricted")

    def test_auth_is_scoped_per_blueprint(self):
        # one blueprint's restrict_to must not speak for a sibling blueprint in the same .rs
        src = """#[blueprint]
mod a {
    enable_method_auth! { methods { mint_it => restrict_to: [admin]; } }
    struct A {}
    impl A { pub fn mint_it(&mut self) {} }
}
#[blueprint]
mod b {
    enable_method_auth! { methods { mint_it => PUBLIC; } }
    struct B {}
    impl B { pub fn mint_it(&mut self) {} }
}
"""
        self.assertEqual(sorted(ln for r, ln in fired(src) if r == "public-mint-burn"), [11])

    def test_commented_out_restriction_does_not_suppress(self):
        # an auth claim written in a comment is not auth — the stripper blanks it, so the rule
        # must not accept it as a gate.
        src = self.RESTRICTED.replace("            mint_manager_badge => restrict_to: [admin, OWNER];",
                                      "            // mint_manager_badge => restrict_to: [admin, OWNER];")
        self.assertIn("public-mint-burn", {r for r, _ in fired(src)})

    def test_no_auth_macro_at_all_still_fires(self):
        self.assertIn("public-mint-burn", {r for r, _ in fired("pub fn mint_free(&mut self) {}")})


class TestOwnerRoleFixed(unittest.TestCase):
    """owner-role-fixed: prepare_to_globalize(OwnerRole::Fixed(...)) — an owner that can never rotate.

    Sibling of owner-role-none, which only matched OwnerRole::None and so reported a component
    with an unrotatable owner (scrypto-xrd wallet-manager, live on mainnet) as clean.
    """

    def test_fires(self):
        src = "let c = x.prepare_to_globalize(OwnerRole::Fixed(rule!(require(badge))));"
        self.assertIn(("owner-role-fixed", 1), fired(src))

    def test_severity_is_low(self):
        # low, not medium: an owner exists, so nothing is immediately exploitable — what is lost
        # is recoverability, and pinning the rule is a legitimate deliberate choice.
        findings = sa.analyze_text("t.rs", "x.prepare_to_globalize(OwnerRole::Fixed(r));")
        self.assertEqual([f["severity"] for f in findings if f["rule"] == "owner-role-fixed"], ["low"])

    def test_rustfmt_wrapped_caught(self):
        src = "let c = x.prepare_to_globalize(\n    OwnerRole::Fixed(rule!(require(badge))),\n);"
        self.assertIn("owner-role-fixed", {r for r, _ in fired(src)})

    def test_updatable_owner_is_clean(self):
        self.assertEqual(fired("x.prepare_to_globalize(OwnerRole::Updatable(rule!(require(b))));"), set())

    def test_owner_role_none_still_its_own_rule(self):
        rules = {r for r, _ in fired("x.prepare_to_globalize(OwnerRole::None);")}
        self.assertIn("owner-role-none", rules)
        self.assertNotIn("owner-role-fixed", rules)

    def test_resource_level_fixed_owner_is_not_flagged(self):
        # the rule is anchored to component globalization. A resource built with a fixed owner
        # is a different (and much narrower) decision — flagging it would be noise.
        src = 'let r = ResourceBuilder::new_fungible(OwnerRole::Fixed(rule!(require(b))));'
        self.assertEqual(fired(src), set())

    def test_suppressible(self):
        src = "x.prepare_to_globalize(OwnerRole::Fixed(r)); // sak:allow owner-role-fixed"
        self.assertEqual(fired(src), set())


class TestHandRolledAddressCheck(unittest.TestCase):
    """hand-rolled-address-check: an address accepted on its prefix, with no bech32m decode.

    scrypto-xrd wallet-manager validates a caller-supplied account address with a prefix test
    plus `len() >= 40` plus `is_ascii_alphanumeric`, then persists it into NFT data that
    off-chain systems read back. No checksum is verified, and that charset admits b/i/o/1,
    which bech32 excludes.
    """

    REAL = ('fn is_valid_account_address(addr: &str) -> bool {\n'
            '    (addr.starts_with("account_rdx1") || addr.starts_with("account_tdx_2_1"))\n'
            '        && addr.len() >= 40\n'
            '        && addr.chars().all(|c| c.is_ascii_alphanumeric() || c == \'_\')\n'
            '}')

    def test_fires_on_the_real_shape(self):
        self.assertIn(("hand-rolled-address-check", 2), fired(self.REAL))

    def test_one_finding_per_line(self):
        # two HRP prefixes chained on one line is one hand-rolled validator, not two findings.
        # Counts raw findings, not the deduplicated (rule, line) set `fired` returns — the set
        # would hide exactly the duplication this asserts against.
        hits = [f for f in sa.analyze_text("t.rs", self.REAL) if f["rule"] == "hand-rolled-address-check"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 2)

    def test_resource_prefix_also_caught(self):
        self.assertIn("hand-rolled-address-check",
                      {r for r, _ in fired('if s.starts_with("resource_rdx1") { ok() }')})

    def test_unrelated_starts_with_is_clean(self):
        self.assertEqual(fired('if name.starts_with("guild_") { ok() }'), set())
        self.assertEqual(fired('if s.starts_with(prefix) { ok() }'), set())

    def test_entity_word_without_hrp_is_clean(self):
        # the rule used to stop at the entity word (`account|resource|component|pool|internal|…`),
        # so ordinary metadata/config keys that merely start with one fired. The network part
        # (`_rdx1` / `_sim1` / `_tdx_<n>_1`) is what makes a literal an address, not a word.
        for key in ("pool_unit_name", "internal_state_v2", "component_address",
                    "resource_limit", "account_label"):
            self.assertEqual(fired(f'if k.starts_with("{key}") {{ }}'), set(), key)

    def test_testnet_and_simulator_hrps_caught(self):
        # the mainnet HRP is `_rdx1`, but a validator written against stokenet (`_tdx_2_1`) or
        # the simulator (`_sim1`) alone is the same hand-rolled check and must still fire.
        self.assertIn("hand-rolled-address-check",
                      {r for r, _ in fired('if a.starts_with("account_tdx_2_1") { ok() }')})
        self.assertIn("hand-rolled-address-check",
                      {r for r, _ in fired('if a.starts_with("account_sim1") { ok() }')})

    def test_comment_does_not_fire(self):
        self.assertEqual(fired('// addr.starts_with("account_rdx1") is not enough'), set())

    def test_wrapped_call_caught(self):
        self.assertIn("hand-rolled-address-check",
                      {r for r, _ in fired('addr.starts_with(\n    "account_rdx1",\n)')})

    def test_bare_prefix_is_only_this_rule(self):
        # hardcoded-address needs 20+ bech32 data chars after the HRP, so the shape this rule is
        # actually about — a bare `account_rdx1` prefix — reports once, not twice.
        rules = [r for r, _ in fired('if a.starts_with("account_rdx1") { ok() }')]
        self.assertEqual(rules, ["hand-rolled-address-check"])

    def test_full_address_reports_both_rules(self):
        # the two address rules are NOT disjoint: `starts_with("<a full address>")` is both a
        # hardcoded address literal and a prefix-only validation, and both fire on that line.
        # That is two distinct problems on one line, so two findings is the intended output —
        # recorded here because the earlier "no overlap" framing was wrong.
        rules = sorted(r for r, _ in fired(
            'if a.starts_with("account_rdx1qcdefghjkmnpqrstuvwxyz23456789") { ok() }'))
        self.assertEqual(rules, ["hand-rolled-address-check", "hardcoded-address"])

    def test_suppressible(self):
        src = 'if a.starts_with("account_rdx1") { ok() } // sak:allow hand-rolled-address-check'
        self.assertEqual(fired(src), set())


if __name__ == "__main__":
    unittest.main()
