# Strategy Vault — STRIDE Threat Model

**Source:** Original threat-modelling exercise on an algorithmic-trading vault design
**Source license:** Apache-2.0 (this file)
**Snapshot date:** 2026-04-27
**Curator:** scrypto-audit-kit contributors

A STRIDE-style threat model for a generic algorithmic-trading vault blueprint with three roles (owner, trader/keeper, guardian). The 20 threats below are concrete enough to compare against most vault-shaped blueprints. Use them as a checklist when auditing any blueprint that custodies user assets and delegates trading authority to a bot.

Method: STRIDE (Spoofing / Tampering / Repudiation / Information disclosure / Denial of service / Elevation of privilege) plus DeFi-specific threat classes.

## Asset inventory (vault-pattern)

What's at risk in a typical trading vault:

| Asset | Quantity | Held in |
|-------|----------|---------|
| User's deposited base asset (e.g. XRD) | up to user's full deposit | `vault.vault_xrd: Vault` |
| User's deposited stables (fUSD, xUSDC, etc.) | up to user's full deposit | `vault.vault_fusd: Vault` |
| Open positions | varies | `vault.open_positions: Vec<Position>` |
| Owner badge | 1 NFT | User's personal account |
| Trader badge | 1 NFT | Bot's account |
| Guardian badge | 1 NFT | Multi-sig holder accounts |

## Trust boundaries

```
┌───────────────────────────────────────────────────────────┐
│ User's Radix Wallet (owner badge holder)                  │
│   → can call: deposit, withdraw, set_policy,              │
│              revoke_trader, panic                         │
├───────────────────────────────────────────────────────────┤
│ Keeper bot (trader badge holder)                          │
│   → can call: enter, close, update_stop                   │
│   → CANNOT: withdraw, change policy, drain                │
├───────────────────────────────────────────────────────────┤
│ Guardian multi-sig (guardian badge, M-of-N)               │
│   → can call: emergency_close_all                         │
│   → CANNOT: withdraw to self                              │
├───────────────────────────────────────────────────────────┤
│ Public                                                    │
│   → can call: nav(), position_state()                     │
│   → read-only state queries                               │
└───────────────────────────────────────────────────────────┘
```

## Adversary models

| Adversary | Goal | Capabilities |
|-----------|------|--------------|
| External attacker (no badges) | Steal funds | Public method calls only |
| Compromised keeper bot | Drain via abusive trades | Can sign trader-badge calls |
| Compromised guardian | Pause + steal | Can sign guardian-badge calls (1 of M) |
| Compromised owner | Self-rug (irrelevant — it's their funds) | All owner methods |
| MEV bot / sandwich attacker | Extract value from trades | Public mempool observation, public swap submission |
| Malicious DEX (compromised pool) | Trick vault into bad swaps | Whitelisted pool component might behave maliciously |
| Oracle manipulator | Move price to trigger / avoid trades | Influence price feed used by vault |

## Threats

### T1 — External attacker calls trader-only method (Elevation)

**Attack:** non-bot calls `vault.enter()` directly via crafted manifest.

**Mitigation:** `enable_method_auth!` declares `enter => restrict_to: [trader]`. Without trader-badge proof in auth zone, method panics at access-rule check before any state mutation.

**Test required:** negative auth test — call without trader badge in auth zone, expect error.

### T2 — External attacker calls owner-only method (Elevation)

**Attack:** anyone calls `vault.withdraw()`, `revoke_trader()`, etc.

**Mitigation:** all owner methods `restrict_to: [OWNER]`. Same mechanism as T1.

**Test required:** negative auth test for every owner method.

### T3 — Compromised bot drains via oversized trade (Tampering)

**Attack:** bot key compromised. Attacker calls `vault.enter()` with `amount = vault.nav()` (entire vault into one trade). Sandwich on the swap. Drain.

**Mitigation:** `assert!(amount <= self.policy.max_trade_pct * self.nav())` BEFORE swap. Hardcoded cap (e.g., 1% NAV per trade).

**Test required:** trade size cap — `vault.enter(amount = nav * 0.5)` exceeds max_trade_pct, expect error.

### T4 — Compromised bot drains via oversized position (Tampering)

**Attack:** bot calls `vault.enter()` repeatedly to build up a single huge position.

**Mitigation:** `assert!(self.position_size_after(...) <= self.policy.max_position_pct * self.nav())`.

**Test required:** repeated entries on same pair, expect cap to trigger after N entries.

### T5 — Compromised bot drains via slippage (Tampering)

**Attack:** bot calls `vault.enter()` with valid amount but routes through a manipulated pool, causing huge slippage. Vault gets pennies for a $1k swap.

**Mitigation:** post-swap NAV check. `assert!(post_nav >= pre_nav * (1 - max_slippage_bps/10000))`. Sommelier-style deviation cap.

**Test required:** simulate a swap where output bucket is much smaller than input, expect post-call assertion to fail.

### T6 — Compromised bot drains via daily loss accumulation (Tampering)

**Attack:** bot makes 100 small losing trades within caps, draining vault by death-of-1000-cuts.

**Mitigation:** `daily_loss_so_far` tracker. `assert!(daily_loss_so_far + estimated_loss <= max_daily_loss_pct * nav)`. If exceeded, all `enter()` calls revert until next day.

**Test required:** simulate N losing trades, expect circuit breaker to trip at threshold.

### T7 — Compromised bot drains via slippage budget consumption (Tampering)

**Attack:** bot makes trades just under per-trade slippage cap, but cumulative slippage drains vault over a week.

**Mitigation:** Enzyme-style cumulative slippage budget. Rolling 7-day window. Each trade's post-call slippage adds to budget. `assert!(slippage_budget_used <= slippage_budget_period_bps)`. Replenishes linearly.

**Test required:** simulate burst trades, expect budget to deny further trades.

### T8 — Compromised bot routes to non-whitelisted component (Tampering)

**Attack:** bot crafts a manifest that calls a malicious component pretending to be Ociswap.

**Mitigation:**
- In scrypto: `assert!(self.policy.allowed_pools.contains(&pool_address))` before swap call.
- Defence in depth: signer-service manifest classifier rejects swap to non-whitelisted address.

**Test required:** call vault.enter() with arbitrary pool address, expect revert.

### T9 — Compromised bot trades non-whitelisted asset (Tampering)

**Attack:** bot tries to swap vault's XRD for a worthless attacker token.

**Mitigation:** `assert!(self.policy.allowed_assets.contains(&token_address))`. allowed_assets defined per strategy.

**Test required:** call enter() with weird token, expect revert.

### T10 — Compromised guardian self-deals via emergency_close_all (Elevation)

**Attack:** guardian calls `emergency_close_all()` then somehow withdraws to self.

**Mitigation:** `emergency_close_all()` only closes positions and returns funds to vault. It does NOT have a `transfer-out` capability. Funds stay in vault. Owner is the only role that can withdraw.

**Test required:** guardian calls emergency_close_all, then attempts withdraw — fails. Funds locked in vault until owner withdraws.

### T11 — User signs malicious manifest disguised as deposit (Spoofing)

**Attack:** phishing site presents a manifest that LOOKS like `vault.deposit(100)` but actually does `vault.set_policy(allowed_pools=[malicious])` followed by `vault.enter()`.

**Mitigation:**
- Manifest decoder library shows decoded intent before signing
- Wallet displays component name (from dApp Definition) — phishing site can't claim a verified dApp's identity without `.well-known/radix.json`
- Risk badges on multi-call manifests
- User education: review every method called

**Test required:** decoder unit tests that show user-readable preview for crafted manifests.

### T12 — DEX pool manipulation (Tampering by external counterparty)

**Attack:** whitelisted pool has been deprecated / drained / manipulated. Vault swaps into it, gets bad output.

**Mitigation:**
- Slippage cap (T5) catches gross underpayment
- Multi-source price oracle (Astrolescent + Pyth) for sanity check pre-swap
- Pool whitelist editable by owner — if a pool becomes bad, owner removes it via `set_policy`

**Test required:** simulate a pool returning 0 output, expect revert via slippage cap.

### T13 — Reentrancy via external pool callback (Tampering)

**Attack:** malicious pool, while processing the vault's swap, re-enters vault to e.g. call enter() again before the first call completes.

**Mitigation:** Scrypto's resource-oriented model + access-rule machinery prevents most reentrancy. Plus: state mutation finalised before any external call where possible.

**Test required:** craft a mock pool that re-enters; vault should detect via state machine assertion.

### T14 — Oracle manipulation (Tampering)

**Attack:** attacker manipulates the oracle price the vault uses for NAV calculation, triggering unfair trades.

**Mitigation:**
- Multi-source oracle (canonical aggregator + on-chain pool TWAP)
- Staleness check: `assert!(oracle.last_update > epoch - max_stale)`
- Sanity bounds on oracle output

**Test required:** stale oracle test, manipulated oracle test.

### T15 — Front-running on entry/exit (Tampering by MEV bot)

**Attack:** MEV bot sees vault's pending swap in mempool, sandwiches it.

**Mitigation:**
- Slippage cap (T5)
- Radix's deterministic transaction model + shorter mempool window
- Eventual: subintent + private mempool if available

**Test required:** post-swap NAV check matches expected within tolerance.

### T16 — Withdrawal blocked by external dependency (Denial of service)

**Attack:** vault's `withdraw()` somehow depends on an external component that's been frozen or malicious.

**Mitigation:** **`withdraw()` is the SIMPLEST possible code path.** No external calls, no oracle deps, no policy hooks. Just role check + fungible vault transfer + emit event.

**Test required:** withdraw works even when vault has zero non-vault assets. Withdraw works even when ALL external pools are unreachable.

### T17 — User loses owner badge (Recovery / Information disclosure)

**Attack:** user's wallet hacked, attacker has owner badge → can withdraw.

**Mitigation (within scrypto):** the badge IS the authority — if attacker holds it, they have the power. Not fixable in scrypto.

**Mitigation (externally):**
- AccessController integration: owner role = `recovery_period(timed_recovery_delay) | confirmation_role`. Attacker holding badge can withdraw immediately, but legitimate owner can `recover()` after delay.
- This requires opt-in by user at vault instantiation.

**Test required:** AccessController flow tests.

### T18 — Performance fee accrual bug (Tampering)

**Attack:** fee logic miscalculates HWM, charges fee on losses.

**Mitigation:**
- Fee charged ONLY when `current_nav > high_water_mark`
- Fee accrued in basis points, capped (e.g., max 30%)
- Fee accrual deterministic from `(nav - hwm) * fee_bps / 10000`

**Test required:** fee accrual tests across various NAV trajectories.

### T19 — State machine corruption (Tampering)

**Attack:** vault enters inconsistent state (e.g., `open_positions` has phantom entries, `vault_xrd` and `nav` calculation diverge).

**Mitigation:**
- Every state mutation paired with corresponding asset move
- Assertion: `nav() == sum_of_vaults() + sum_of_position_values()`
- Idempotent state transitions

**Test required:** invariant test — after every method call, `assert_invariant(vault)` passes.

### T20 — Out-of-gas during critical path (Denial of service)

**Attack:** transaction fee budget too low for vault's complex tx; entry fails partway, vault left in inconsistent state.

**Mitigation:**
- All state mutations atomic (Radix transaction semantics)
- Pre-method gas estimation in client
- Conservative `lock_fee` minimums

**Test required:** stress test with low fee budgets, verify atomicity.

## Load-bearing mitigations summary

The four in-scrypto mitigations that, if broken, make the vault unsafe:

1. **Method-level role auth** (`enable_method_auth!`)
2. **Hard caps via `assert!` before any external call** (max_trade_pct, max_position_pct, max_daily_loss_pct, slippage_budget)
3. **Pool/asset whitelist** (allowed_pools, allowed_assets in policy)
4. **Withdraw is simplest possible code path** — owner-only, no externals, never blocked

Audit must verify all four are present and correctly implemented in any vault-shaped blueprint.

## What's deliberately NOT mitigated

- **User loses owner badge** — outside vault scope, opt-in AccessController
- **Strategy logic is bad** — vault enforces caps, doesn't validate strategy quality
- **Audit catches a critical bug** — can happen, mitigate via bug bounty + emergency `panic()` + simple `withdraw()` always works
- **DEX/protocol underlying gets exploited** — composability blast radius. Mitigate via whitelist + diversification.

## Audit checklist (handed to external auditor)

- [ ] All 20 threats individually verified
- [ ] All 4 load-bearing mitigations are present and correctly implemented
- [ ] Code coverage ≥ 90% on policy assertions
- [ ] All public methods have positive + negative test
- [ ] No `unwrap()` or `expect()` on user-controlled inputs
- [ ] No mutable globals
- [ ] All `assert!` use error constants from `define_error!` macro
- [ ] Vault address is reproducible from constructor inputs (deterministic instantiation)
- [ ] Withdraw method is simplest possible — no external calls, no policy hooks
- [ ] Bug bounty configured (≥$10k for critical)
- [ ] Emergency panic mode tested
