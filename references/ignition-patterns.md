# Ignition — Scrypto Reference Patterns

**Source:** [radixdlt/Ignition](https://github.com/radixdlt/Ignition)
**Source license:** Apache-2.0
**Snapshot date:** 2026-04-27
**Curator:** scrypto-audit-kit contributors

Ignition is a production-grade upgradeable multi-DEX liquidity-incentive protocol maintained by the Radix team. It's the canonical Radix-side reference codebase. The patterns below are extracted as concrete examples for comparing other blueprints against. Cite the Ignition source when raising findings ("does the target implement Ignition pattern N?").

## Repo layout (for orientation)

```
Cargo.toml              workspace root
Makefile.toml           cargo-make tasks (cross-package build/test)
rust-toolchain.toml     pinned toolchain
packages/               on-ledger blueprints, each its own crate
  ignition/             core protocol (~2030 lines)
  caviarnine-v1-adapter-v1/
  defiplaza-v2-adapter-v1/
  ociswap-v1-adapter-v1/
  ociswap-v2-adapter-v1/
  simple-oracle/
libraries/              reusable Rust crates
  scrypto-interface/    define_interface! + blueprint_with_traits! macros
  ports-interface/      shared PoolAdapter / OracleAdapter interface defs
  common/               LiquidityReceipt, Price, AnyValue, LockupPeriod, Volatility
  address-macros/, gateway-client/, package-loader/, scrypto-math/
testing/
  tests/                unit/integration via scrypto-test + TestRunner
  stateful-tests/       runs against real mainnet substate DB via overlay
tools/
  package-dumper/       dumps closed-source packages from a node DB for tests
  publishing-tool/      declarative deployer driving Gateway like a TestRunner
```

**Test tier model:**
- **Smoke** — `scrypto-test` `TestEnvironment`
- **Integration** — `TestRunner` against in-memory ledger
- **Stateful** — `SubstateDatabaseOverlay` over a synced node DB so writes go to memory only. Catches bugs that local-pool tests miss (per Ignition README, fee-limit issues only appeared in stateful tests).

`#[apply(mainnet_test)]` declarative macro injects `notary`, `PublishingReceipt`, `StatefulTestRunner` into each test.

## Pattern 1: Two-tier role hierarchy — owner vs manager

`packages/ignition/src/blueprint.rs:107`:

```rust
enable_method_auth! {
    roles {
        protocol_owner   => updatable_by: [protocol_owner];
        protocol_manager => updatable_by: [protocol_manager, protocol_owner];
    },
    methods {
        set_oracle_adapter            => restrict_to: [protocol_owner, protocol_manager];
        add_allowed_pool              => restrict_to: [protocol_owner, protocol_manager];
        set_is_open_position_enabled  => restrict_to: [protocol_owner, protocol_manager];
        // High-stakes methods owner-only:
        deposit_protocol_resources    => restrict_to: [protocol_owner];
        withdraw_protocol_resources   => restrict_to: [protocol_owner];
        forcefully_liquidate          => restrict_to: [protocol_owner];
        open_liquidity_position       => PUBLIC;
        close_liquidity_position      => PUBLIC;
    }
}
```

**Manager** flips operational flags + registry pointers (oracles, adapters, allowed pools). **Owner** alone holds vault egress + forced liquidation. `protocol_manager` can rotate itself; `protocol_owner` rotates only via owner.

This maps to agent-wallet patterns: instantiate with `protocol_manager_role = AccessRule::require(<bot signer NFT>)` and `protocol_owner_role = AccessRule::require(<cold multisig>)`. Bot can pause trading, swap oracle, register pools — but cannot drain.

Composite rules: `rule!(require_amount(2, signers))` gives M-of-N out of the box.

## Pattern 2: `scrypto-interface` for multi-protocol abstraction

`libraries/ports-interface/src/pool.rs` defines once:

```rust
define_interface! {
    PoolAdapter impl [
        #[cfg(feature = "trait")]                  Trait,
        #[cfg(feature = "scrypto-stubs")]          ScryptoStub,
        #[cfg(feature = "scrypto-test-stubs")]     ScryptoTestStub,
    ] {
        fn open_liquidity_position(
            &mut self,
            pool_address: ComponentAddress,
            #[manifest_type = "(ManifestBucket, ManifestBucket)"]
            buckets: (Bucket, Bucket),
        ) -> OpenLiquidityPositionOutput;
        fn close_liquidity_position(...) -> CloseLiquidityPositionOutput;
        fn price(&mut self, pool_address: ComponentAddress) -> Price;
        fn resource_addresses(&mut self, pool_address: ComponentAddress)
            -> (ResourceAddress, ResourceAddress);
    }
}
```

Macro generates four artifacts (selectable via feature flags):
1. **Trait** (`PoolAdapterInterfaceTrait`) — implemented by each adapter blueprint
2. **ScryptoStub** — typed call site: `let mut adapter: PoolAdapter = component_address.into();`
3. **ScryptoTestStub** — same, for the test environment
4. **ManifestBuilderStub** — extension methods on `ManifestBuilder` with `#[manifest_type = "ManifestBucket"]` swapping in manifest-side types

Adapters use `#[blueprint_with_traits]` (drop-in for `#[blueprint]` that allows `impl SomeTrait for Component`):

```rust
#[blueprint_with_traits]
pub mod adapter {
    struct OciswapV2Adapter;
    impl OciswapV2Adapter { fn instantiate(...) -> Global<Self> { ... } }
    impl PoolAdapterInterfaceTrait for OciswapV2Adapter {
        fn open_liquidity_position(...) -> OpenLiquidityPositionOutput { ... }
        // compile-time error if any method drifts from the interface
    }
}
```

**Address parameterisation:** core never hardcodes pool addresses. Stores `KeyValueStore<BlueprintId, StoredPoolBlueprintInformation>` where `BlueprintId = (PackageAddress, blueprint_name)`. Pool components get bucketed by their blueprint via `ScryptoVmV1Api::object_get_blueprint_id(pool_address.as_node_id())`. Switching adapter for an exchange = mutating one map entry; no migration.

Blueprints integrating multiple external protocols should use this pattern. Define the interface once; one adapter per protocol implements it.

## Pattern 3: Vault topology (three vault families)

```rust
struct Ignition {
    protocol_resource_reserves:   ProtocolResourceReserves,        // split volatile/non-volatile
    user_resources_vaults:        KeyValueStore<ResourceAddress, FungibleVault>,
    pool_units:                   KeyValueStore<NonFungibleGlobalId,
                                                IndexMap<ResourceAddress, Vault>>,
    forced_liquidation_claims:    KeyValueStore<NonFungibleGlobalId, Vec<Vault>>,
    ...
}
```

`ProtocolResourceReserves` splits the protocol asset (XRD) into `volatile` and `non_volatile` `FungibleVault`s — segregates IL exposure by user-asset class. Settable per-asset via `Volatility::Volatile | NonVolatile`.

## Pattern 4: Pre-call / post-call invariant checks (Sommelier-style)

`blueprint.rs:540-595` (open) and `:855-880` (close):

```rust
let oracle_reported_price = self.checked_get_price(user_resource, protocol_resource);
let pool_reported_price   = adapter.price(pool_address);
let relative_difference   = oracle_reported_price.relative_difference(&pool_reported_price)
                                .expect(USER_ASSET_DOES_NOT_BELONG_TO_POOL_ERROR);
assert!(
    relative_difference <= self.maximum_allowed_price_difference_percentage,
    "{}", RELATIVE_PRICE_DIFFERENCE_LARGER_THAN_ALLOWED_ERROR
);
```

Plus a second invariant — protocol resource withdrawn cannot exceed `(1 + max_diff) * oracle_value` of user's contribution (`blueprint.rs:580`), bounding worst-case protocol exposure if oracle AND pool are both off.

Staleness via `checked_get_price` (`blueprint.rs:1818`): adds `maximum_allowed_price_staleness_in_seconds` to oracle's `last_update` and asserts `Clock::current_time_is_at_or_before(...)`.

## Pattern 5: Asymmetric circuit breakers

`is_open_position_enabled` and `is_close_position_enabled` are **independent flags**. In a bug scenario, open disabled while close stays enabled so users can exit. `forcefully_liquidate` works regardless of either flag — owner has always-available recovery.

Blueprints that gate user actions should split deposit / trade / withdraw flags rather than collapsing them. Default: emergencies disable trading first, withdrawals last.

## Pattern 6: `AnyValue` for forward-compatible schemas

`libraries/common/src/any_value.rs`:
- `#[sbor(transparent)] struct AnyValue((ScryptoValue,))`
- `from_typed<T: ScryptoEncode>` / `as_typed<T: ScryptoDecode>` round-trip through `scrypto_encode`/`scrypto_decode`

Core stores opaque blob; adapters own codec. Lets receipt NFTs hold adapter-specific data without core knowing the schema. Useful when migrating adapters without invalidating receipts.

## Pattern 7: `Price` as typed pair (prevents direction bugs)

`libraries/common/src/price.rs`:
```rust
struct Price { base, quote, price }
```

Carries asset addresses. `relative_difference` and `exchange` accept either direction and inverse-flip if needed. **Prevents the common "I multiplied when I should have divided" bug at the type level.**

Any blueprint that does price comparisons or calculations should use a typed Price helper, not raw `Decimal`.

## Pattern 8: Error constants via `define_error!` macro

`packages/ignition/src/errors.rs`:

```rust
macro_rules! define_error {
    ($($name:ident => $item:expr;)*) => {
        $( pub const $name: &'static str = concat!("[Ignition]", " ", $item); )*
    };
}
define_error! {
    NO_ADAPTER_FOUND_FOR_POOL_ERROR                       => "No adapter found for liquidity pool.";
    OPENING_LIQUIDITY_POSITIONS_IS_CLOSED_ERROR           => "Opening liquidity positions is disabled.";
    ORACLE_REPORTED_PRICE_IS_STALE_ERROR                  => "Oracle reported price is stale.";
    RELATIVE_PRICE_DIFFERENCE_LARGER_THAN_ALLOWED_ERROR   => "...";
    LIQUIDITY_POSITION_HAS_NOT_MATURED_ERROR              => "...";
    OVERFLOW_ERROR                                        => "Overflow error";
    // ~24 total
}
```

Each adapter has its own re-instantiation with a different prefix (`[Ociswap v2 Adapter v1]`). Log-greppable error origins. Used everywhere via `assert!(cond, "{}", ERROR_CONST)` and `.expect(ERROR_CONST)`.

Every blueprint should define its own error catalogue with a project-specific prefix.

## Pattern 9: Forced-liquidation as separate terminal state

`blueprint.rs:705-790`. `forcefully_liquidate` runs the same `liquidate()` as a normal close BUT stages buckets into `forced_liquidation_claims` instead of returning them. `close_liquidity_position` checks this map first — if found, just burns the receipt and returns the staged buckets.

**Decouples privileged action from user's claim time.** Owner can pull the trigger; user claims when convenient. Applicable to any emergency-pause / panic flow.

## Pattern 10: Address pre-allocation for deterministic per-user spawning

`Runtime::allocate_component_address` + optional `address_reservation: Option<GlobalAddressReservation>` parameter in `instantiate`. A parent component can pre-allocate and pass in addresses for child components → deterministic per-user vault spawning.

For per-user-per-strategy component topologies, this enables:
- Frontend computes the vault address before user signs
- Manifest preview shows "your vault will be at address X"
- User signs, address X is the actual vault — no surprise

## Pattern 11: No events emitted (deliberate)

Ignition core emits **no custom events**. NFT minting/burning IS the event, indexable via Gateway. Off-chain reads NFT data + substate diffs.

This is a *choice*, not a default. Blueprints with latency-sensitive off-chain notifications (UI, alerts, indexers needing sub-second updates) should emit events for every state-changing action. Audit each blueprint's emission strategy against its consumers.

## Pattern 12: Stateful tests against mainnet substate

`SubstateDatabaseOverlay` over a synced node DB. Tests get real Ociswap/CN/DefiPlaza pool state. Writes go to memory only.

Catches bugs local pools never expose (per Ignition README: "the bug appeared *only* in stateful tests").

Every blueprint that integrates with external protocols should have stateful tests against real mainnet substates before audit submission.

## Pattern 13: `Vec<Bucket> others` passthrough channel

Adapter outputs include a `Vec<Bucket> others` for unanticipated returns (e.g. exchange-side reward emissions). Core does not interpret them; just appends to what's returned to the caller. Forward-compatible against future protocol changes.

## Pattern 14: `InitializationParametersManifest` mirroring `InitializationParameters`

Two parallel structs — one with `FungibleBucket`, one with `ManifestBucket` — bridging the manifest/scrypto type gap for constructor params. The `define_interface!` macro automates this for method args; constructor params need it manually.

## Files referenced (for verification)

- `packages/ignition/src/blueprint.rs` — core protocol (~2030 lines)
- `packages/ignition/src/errors.rs` — error-constant macro
- `packages/simple-oracle/src/lib.rs` — minimal interface impl
- `packages/ociswap-v2-adapter-v1/src/lib.rs` — adapter exemplar
- `libraries/scrypto-interface/README.md` — the macro
- `libraries/scrypto-interface/src/decl_macros.rs`, `src/handlers.rs` — implementation
- `libraries/ports-interface/src/{pool,oracle}.rs` — interface defs
- `libraries/common/src/{liquidity_receipt,price,any_value,volatility,lockup_period}.rs` — reusable types
- `tools/publishing-tool/src/configuration_selector/mainnet_production.rs` — production rule wiring
- `testing/stateful-tests/` — `#[apply(mainnet_test)]` macro
- `tools/package-dumper/` — substate dumping for closed-source third-party packages
