//! Intentionally thin test suite — only the deposit happy path is covered.
//!
//! What's deliberately MISSING (so the kit has test-coverage gaps to report):
//!   - no auth-violation test (e.g. a non-admin calling a restricted method)
//!   - no `withdraw` test at all
//!   - no "withdraw while paused" negative test
//!   - no over-bound `set_fee_bps` test
//!   - no oracle-staleness / price-sanity test

use scrypto_test::prelude::*;

#[test]
fn deposit_happy_path() {
    let mut env = TestEnvironment::new();
    let package = PackageFactory::compile_and_publish(this_package!(), &mut env, CompileProfile::Fast)
        .expect("compile");

    let (mut vault, _admin_badge): (VulnerableVault, Bucket) =
        VulnerableVault::instantiate(dec!(1), package, &mut env).expect("instantiate");

    let xrd = BucketFactory::create_fungible_bucket(XRD, dec!(100), Mock, &mut env).unwrap();
    let shares = vault.deposit(xrd, &mut env).expect("deposit");

    // Only asserts the success path returns *something*.
    assert!(shares.amount(&mut env).unwrap() >= dec!(0));
}
