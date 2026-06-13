# CaviarNine HyperStake / LSU Pool — Scrypto Patterns

**Source:** [caviarnine/caviarnine-scrypto](https://github.com/caviarnine/caviarnine-scrypto)
**Source license:** Apache-2.0
**Snapshot date:** 2026-04-27
**Curator:** scrypto-audit-kit contributors

CaviarNine open-sources all of its production scrypto blueprints in one Apache-licensed monorepo. The HyperStake module wraps an LSULP↔XRD concentrated-band pool over the underlying LSULP multi-LSU pool. Scrypto **1.2.0** at snapshot.

## Repo structure

Top-level fan-out of single-blueprint crates, each a separate `[workspace]`:

```
fee_controller/  fee_vaults/        hyper_stake/      lsu_pool/
lsu_token_validator/  order_book/   order_book_factory/
quantaswap/  quantaswap_factory/    token_bridge/  token_creator/
token_validator/  weighted_pool/
```

`hyper_stake/` itself wraps three crates: `hyper_stake/` (real blueprint), `mock_fee_vaults/`, `mock_lsu_pool/` (test deps). Build profile uses standard size-optimised Scrypto preset (`opt-level='z'`, `lto`, `panic='abort'`, `overflow-checks=true`).

**Build-time address injection** — `lsu_pool/build.rs` generates `env_constants.rs` so addresses (LSULP_RESOURCE, LSU_POOL_COMPONENT, FEE_VAULTS_COMPONENT, OWNER_RESOURCE) come from env vars at compile time. Same binary builds for sim/stokenet/mainnet just by changing env vars. Cleaner than hardcoding.

## Patterns

### 1. Wrap `TwoResourcePool` instead of reinventing LP

HyperStake's whole accounting is ~50 lines because Radix's native pool does the work.

```rust
// hyper_stake.rs:71
struct HyperStake {
    resource_pool: Global<TwoResourcePool>,
    // no per-position state — TwoResourcePool's LP unit token is the receipt
}
```

`add_liquidity()` is just `self.resource_pool.contribute((x, y))` then emit event. `remove_liquidity()` is `self.resource_pool.redeem(lp)` then emit. **Per-LP accounting delegated entirely to the native pool.**

Any blueprint holding a 2-asset position should reach for `TwoResourcePool` first.

### 2. Per-deposit soul-bound `CreditReceipt` NFT with mutable HashMap

```rust
// lsu_pool/src/credit_receipt.rs:3-9
#[derive(ScryptoSbor, NonFungibleData)]
pub struct CreditReceipt {
    #[mutable] pub resources: HashMap<ResourceAddress, Decimal>,
}
```

`#[mutable]` field updated in-place via `update_non_fungible_data`. Per asset deposited, the receipt remembers cumulative amount. Combine with `merge_credit(p1, p2)` so users don't accumulate receipt clutter.

### 3. Lazy round-robin price/NAV updates

Every state-changing call begins with `update_multiple_validator_prices(N)` — round-robin pointer iterates the validator map, refreshing N prices per call. **Bounds per-call cost to a constant**, never a global revaluation loop.

```rust
// lsu_pool.rs:785-808
fn get_validator_price_and_update_valuation(...) {
    self.dex_valuation_xrd += vault_amount * (new_price - old_price);
}
```

Vaults that need up-to-date NAV can use this pattern to avoid per-call O(N) loops over all positions.

### 4. Always round in vault favour

```rust
// hyper_stake/hyper_stake/src/hyper_stake/consts.rs:6-7
pub const INCOMING: WithdrawStrategy = WithdrawStrategy::Rounded(RoundingMode::ToPositiveInfinity);
pub const OUTGOING: WithdrawStrategy = WithdrawStrategy::Rounded(RoundingMode::ToZero);
```

Used everywhere: `take_advanced(amount, INCOMING|OUTGOING)`. Any blueprint that does decimal arithmetic between user-side and vault-side amounts should adopt this convention universally — round-up on receipts to the vault, round-down on payouts to users.

### 5. Updatable roles — public-by-default with whitelist option later

```rust
// hyper_stake.rs:42-57
enable_method_auth! {
    roles {
        liquidity_user => updatable_by: [OWNER];
        swap_user      => updatable_by: [OWNER];
    },
    methods {
        add_liquidity     => restrict_to: [liquidity_user];
        swap              => restrict_to: [swap_user];
        remove_liquidity  => PUBLIC;  // never gated
    }
}
// At globalize:
.roles(roles!(liquidity_user => rule!(allow_all); swap_user => rule!(allow_all);))
```

Ship public, reserve the ability to lock to a whitelist by rotating the role rule. Allows blueprints to start permissionless and add controls later without redeployment.

### 6. Public `remove_liquidity` always

Withdraws can never be gated. Same pattern in HyperStake AND LSULP. This is a strong invariant: **a user's exit path should never depend on policy state**.

### 7. Build-time address constants via `build.rs` + `OUT_DIR`

```rust
include!(concat!(env!("OUT_DIR"), "/env_constants.rs"));
```

Same binary, different addresses per network. Cleaner than hardcoded addresses or runtime address registration.

### 8. Three-way fee split

```rust
// hyper_stake.rs:483-486
let protocol_fee = total_fee * self.protocol_fee_share;
let treasury_fee = total_fee * self.treasury_fee_share;
let liquidity_fee = total_fee - protocol_fee - treasury_fee;  // residual to LPs
```

Bounded `protocol_fee_share + treasury_fee_share <= 0.1`. Liquidity fee is the residual. Simple, auditable.

### 9. Tag-rich, updatable resource metadata

Every LP token gets `swap_component`, `info_url`, `tags=["dex","LP token"]`, `icon_url`. Wallet/dashboard rendering needs this.

### 10. Single `get_info()` getter returning structured `PoolInfo`

```rust
// structs.rs:3-18 — 13 fields in one call
pub struct PoolInfo { ... }
```

Single-call introspection beats reading 13 metadata keys.

### 11. Validator-flooding penalty

```rust
// lsu_pool.rs:1042-1046
if validator_counter > validator_max_before_fee {
    take(num.pow(3))   // cubic penalty
}
```

Anti-spam: cube the penalty for piling into many tiny validators. Generalisable to any system that maps users to integrations.

### 12. Test mocks as separate path-dep crates

`mock_fee_vaults/` and `mock_lsu_pool/` live as sibling crates referenced via `Cargo.toml:13-14` path-deps. Tests get realistic external behaviour without booting full network.

## Concentrated/shape liquidity math (HyperStake's core)

Single virtual-band around an oracle price:

1. Each block: `oracle_price = lsu_pool.get_dex_valuation_xrd() / total_LSULP_supply` — LSULP redemption value derived from validator staking issue prices
2. `upper_limit = sqrt(oracle * upper_offset)`, `lower_limit = sqrt(oracle * lower_offset)`
3. `calculate_virtual_amounts(real_x, real_y, ul, ll)` solves a quadratic for `liq` such that real reserves are exhausted exactly at band edges
4. Returns inflated `virtual_x = x + liq/ul`, `virtual_y = y + liq*ll`
5. Standard constant-product math against virtual amounts: `output = input * vy / (vx + input)`

**All math in `I512` with base `10^36`** for precision, then converted back to `Decimal` (`I192`). Fee bounded `0.0001 <= fee <= 0.02`.

The precision pattern (`I512` base `10^36`) is worth copying for any high-precision math.

## Test stack

Two coexist:
- **scrypto-test 1.2.0** (HyperStake, newer) — direct typed calls: `pool.get_info(env)?`. `setup()` returns `(vars, env)` with mocks pre-instantiated.
- **TestRunner manifest-based** (LSULP, older) — builds receipts, asserts `receipt.expect_commit_success()` and `assert_contains_message(receipt, "Can only add LSU tokens as liquidity.")`. Tests realistically build full LSU resources via `validator::create_lsu_resource(&mut vars, dec!(100))`. Cost checked via `receipt.fee_summary.total_execution_cost_in_xrd`.

Tests don't touch real on-chain state — they reproduce validator set in-process via `mock_lsu_pool` + `lsu_token_validator`.

## Integration points

For blueprints integrating WITH HyperStake (as a yield source, not as a re-implementation):

```rust
extern_blueprint!(
    "package_rdx1...",  // mainnet HyperStake package address
    HyperStake {
        fn add_liquidity(&mut self, token_x: Bucket, token_y: Bucket) -> (Bucket, Option<Bucket>);
        fn remove_liquidity(&mut self, lp: Bucket) -> (Bucket, Bucket);
        fn get_info(&mut self) -> PoolInfo;
    }
);
```

Methods needed:
- `add_liquidity(x, y) -> (lp, remainder)` — deposit
- `remove_liquidity(lp) -> (x, y)` — withdraw
- `get_info()` — for valuation, slippage estimation, NAV calc

**Keep integration surface minimal** — exactly what HyperStake itself did with LsuPool (one method: `get_dex_valuation_xrd`).

## Notable / surprising

- **No flash-loan interface** in HyperStake — strictly a swap pool
- **`new_with_tokens` bootstraps + seeds in one tx** — auto-sets price by depositing then calling `add_liquidity`
- **`extern_blueprint!` style differs** — LsuPool uses older `package_sim1...` + `global_component!` macro; HyperStake uses newer `_FEE_VAULTS_PACKAGE` build-time constants. Use the newer style.
- **Reserve-fee for stranded LSUs** — collected into `reserve_vaults` per LSU; OWNER can `take_from_reserve_vaults` to manually rebalance against deactivated validators. Closest the protocol gets to active management.
- **Test file typo `test_initialiasation.rs`** — left in mainline. Signals "shipping > polish".

## Files referenced

- `hyper_stake/hyper_stake/src/hyper_stake.rs` — main blueprint
- `hyper_stake/hyper_stake/src/hyper_stake/consts.rs:6-7` — INCOMING/OUTGOING constants
- `lsu_pool/src/lib.rs` — multi-LSU pool
- `lsu_pool/src/credit_receipt.rs:3-9` — NFT receipt pattern
- `lsu_pool/build.rs` — build-time address injection
