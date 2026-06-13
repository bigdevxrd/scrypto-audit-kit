# Radix / Scrypto — General Knowledge Base

**Source:** Original notes compiled from production DeFi work on Radix mainnet
**Source license:** Apache-2.0 (this file)
**Snapshot date:** 2026-04-27
**Curator:** scrypto-audit-kit contributors

A grab-bag of practical Radix knowledge — transaction fundamentals, pool types and their interfaces, common manifest patterns, mainnet resource addresses, and guard rails learned from real-world incidents. Useful baseline context when auditing any blueprint that touches the wider Radix ecosystem.

## Transaction fundamentals

### Lock fee

- ALWAYS use `Decimal("5")` minimum (1 XRD insufficient for complex swaps)
- Fee is locked from account, unused portion returned automatically
- Complex TXs (multi-hop swaps, LP operations) can cost 1-2 XRD in fees

### Withdraw precision

- Radix does NOT support "withdraw all" — must specify exact amount
- ALWAYS floor amounts to avoid dust: `Math.floor(amount * 1e15) / 1e15`
- `InsufficientBalance` errors from dust: 0.000000002 XRD difference kills TX
- For "withdraw all" pattern: query exact on-chain balance first, use that value

### Account model

- Each account is a separate on-chain component
- One seed → one derivation path → one account (no sub-accounts)
- Multiple accounts need multiple derivation paths (BIP44)
- Ed25519 signing is the default

## Pool types (when auditing integrations)

### 1. Native Two-Resource Pool

- Method: `redeem(Bucket)` to withdraw (NOT `remove_liquidity`)
- Returns fungible pool unit token
- Example: DefiPlaza pools, some Ociswap basic pools

### 2. Ociswap V2 Precision Pool

- Method: `remove_liquidity(Bucket)` with fungible LP token
- Returns both pool assets
- LP token identified via pool metadata `lp_address`

### 3. CaviarNine Shape Liquidity

- Uses NFT receipt for position tracking (NOT fungible LP)
- Concentrated liquidity — position has price range
- LSULP is the pooled LSU version
- Removal requires the specific NFT receipt
- More complex — needs dedicated removal script

### 4. Weft Lending

- Supply/borrow model with collateral
- LSU tokens as collateral
- Different method interface (deposit/withdraw/borrow/repay)

**Audit implication:** if a blueprint integrates with a pool, verify it's calling the right method (`redeem` vs `remove_liquidity` vs receipt-based) for that pool type. Wrong method = stuck funds.

## Manifest patterns (for reference when reviewing client-side code)

### Stake XRD

```
CALL_METHOD Address("{account}") "lock_fee" Decimal("5");
CALL_METHOD Address("{account}") "withdraw" Address("{XRD}") Decimal("{amount}");
TAKE_ALL_FROM_WORKTOP Address("{XRD}") Bucket("xrd");
CALL_METHOD Address("{validator}") "stake" Bucket("xrd");
CALL_METHOD Address("{account}") "deposit_batch" Expression("ENTIRE_WORKTOP");
```

### Unstake (returns claim NFT, 7-day wait)

```
CALL_METHOD Address("{account}") "lock_fee" Decimal("5");
CALL_METHOD Address("{account}") "withdraw" Address("{lsu_token}") Decimal("{amount}");
TAKE_ALL_FROM_WORKTOP Address("{lsu_token}") Bucket("lsu");
CALL_METHOD Address("{validator}") "unstake" Bucket("lsu");
CALL_METHOD Address("{account}") "deposit_batch" Expression("ENTIRE_WORKTOP");
```

### Swap (single hop)

```
CALL_METHOD Address("{account}") "lock_fee" Decimal("5");
CALL_METHOD Address("{account}") "withdraw" Address("{sell_token}") Decimal("{amount}");
TAKE_ALL_FROM_WORKTOP Address("{sell_token}") Bucket("swap_in");
CALL_METHOD Address("{pool_component}") "swap" Bucket("swap_in");
CALL_METHOD Address("{account}") "deposit_batch" Expression("ENTIRE_WORKTOP");
```

### Add LP (Ociswap V2)

```
CALL_METHOD Address("{account}") "lock_fee" Decimal("5");
CALL_METHOD Address("{account}") "withdraw" Address("{token_y}") Decimal("{y_amount}");
CALL_METHOD Address("{account}") "withdraw" Address("{token_x}") Decimal("{x_amount}");
TAKE_ALL_FROM_WORKTOP Address("{token_y}") Bucket("y_bucket");
TAKE_ALL_FROM_WORKTOP Address("{token_x}") Bucket("x_bucket");
CALL_METHOD Address("{pool}") "add_liquidity" Bucket("y_bucket") Bucket("x_bucket");
CALL_METHOD Address("{account}") "deposit_batch" Expression("ENTIRE_WORKTOP");
```

### Remove LP (Ociswap V2 - fungible LP token)

```
CALL_METHOD Address("{account}") "lock_fee" Decimal("5");
CALL_METHOD Address("{account}") "withdraw" Address("{lp_token}") Decimal("{exact_amount}");
TAKE_ALL_FROM_WORKTOP Address("{lp_token}") Bucket("lp_bucket");
CALL_METHOD Address("{pool}") "remove_liquidity" Bucket("lp_bucket");
CALL_METHOD Address("{account}") "deposit_batch" Expression("ENTIRE_WORKTOP");
```

### Redeem Native Pool Units

```
CALL_METHOD Address("{account}") "lock_fee" Decimal("5");
CALL_METHOD Address("{account}") "withdraw" Address("{pool_unit}") Decimal("{amount}");
TAKE_ALL_FROM_WORKTOP Address("{pool_unit}") Bucket("lp_bucket");
CALL_METHOD Address("{pool_address}") "redeem" Bucket("lp_bucket");
CALL_METHOD Address("{account}") "deposit_batch" Expression("ENTIRE_WORKTOP");
```

## Known mainnet resources (public ledger data)

| Token | Address |
|-------|---------|
| XRD | `resource_rdx1tknxxxxxxxxxradxrdxxxxxxxxx009923554798xxxxxxxxxradxrd` |
| fUSD | `resource_rdx1t49wa75gve8ehvejr760g3pgvkawsgsgq0u3kh7vevzk0g0cnsmscq` |
| LSULP | `resource_rdx1thksg5ng70g9mmy9ne7wz0sc7auzrrwy7fmgcxzel2gvp8pj0xxfmf` |
| EARLY | `resource_rdx1t5xv44c0u99z096q00mv74emwmxwjw26m98lwlzq6ddlpe9f5cuc7s` |

## Known mainnet pools (public ledger data)

| Pool | Component | Type |
|------|-----------|------|
| Ociswap fUSD/XRD | `component_rdx1cpmacy5gwzswse56jprvlfhrpnt3mplswupu7qtq8pdz2hywy5uaqd` | Ociswap V2 |
| CaviarNine LSULP/XRD | `component_rdx1crdhl7gel57erzgpdz3l3vr64scslq4z7vd0xgna6vh5fq5fnn9xas` | Shape Liquidity |
| DefiPlaza hETH/xETH | `component_rdx1cr4lw3pfgeel7fex4ur53k7k63s5wu3q28mtr5mpp3hddug55pfwy3` | DefiPlaza |

## Guard rails (lessons from incidents)

### Before any DeFi TX:

1. Query pool on-chain state — check both token balances are non-zero
2. Query account balance — verify the exact amount is available
3. Preview the TX via Radix preview API if available
4. Show manifest to user in human-readable format
5. Get explicit confirmation before executing
6. One TX at a time, verify each before next

### Before any swap:

1. Check pool liquidity (TVL > 10,000 XRD minimum)
2. Preview slippage via Ociswap/Astrolescent preview API
3. Set minimum output amount (NOT 0)
4. Never swap into a pool with one-sided liquidity

### Before any LP deposit:

1. Verify BOTH tokens exist in the pool with meaningful balance
2. Check current pool ratio matches expected price
3. Preview the LP amount that would be received
4. Never deposit into an empty or one-sided pool

### Rounding:

- Always floor amounts: `Math.floor(n * 1e15) / 1e15`
- For "all" withdrawals: query exact balance, use that value
- Account for fee deduction (lock_fee reduces available XRD)

## Implications for blueprint audits

When a blueprint integrates with the wider ecosystem:

- **Hardcoded addresses** are a finding — addresses should come from constructor params, environment, or a whitelist KVS. Pool addresses do change (deprecation, migration); resource addresses don't, but the principle of avoiding hardcoded externalities still applies.
- **Method-name assumptions** are a finding — `swap` vs `swap_exact_in` vs `exchange` all exist on different pool types. The blueprint must declare which pool type each whitelisted pool is, and call the right method.
- **No slippage / min-out** is a finding — every swap call must pass a non-zero minimum output, derived from a fresh price quote.
- **No staleness check on price feed** is a finding — see Ignition pattern 4.
