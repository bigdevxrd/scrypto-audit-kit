<!-- scrypto-audit-kit 0.1.0 · model anthropic/claude-sonnet-4-6 · checklist 1.0 · source 67bd50984ac3 · 2026-06-13 -->
# Audit: vulnerable-vault

### 1. Summary

`vulnerable-vault` is a toy single-asset yield vault: users `deposit` XRD and receive vault shares priced against an oracle, and an `admin` can tune the fee, pause, and (supposedly) protect funds. It is a deliberately-vulnerable fixture — every issue below is planted. Two independent paths let an unprivileged caller drain the entire vault, the deposit pricing math panics on the very first deposit, and the pause switch does not stop withdrawals.

- **Asset inventory**: XRD held in `self.vault` (`src/lib.rs:37`, initialised `src/lib.rs:60`); share tokens minted on deposit (`src/lib.rs:38`, `src/lib.rs:90`); a single `admin` badge minted at instantiation (`src/lib.rs:48`–`50`).
- **Trust boundaries**: one role, `admin`, gating `set_fee_bps`/`pause`/`unpause` and declared `updatable_by` *itself* (`src/lib.rs:20`–`34`). Everything else — `deposit`, `withdraw`, `set_oracle_price`, `emergency_drain` — is `PUBLIC` (`src/lib.rs:26`–`30`).
- **External dependencies**: none. The "oracle" is an internal struct field (`src/lib.rs:40`), not an external component — the price is simply whatever was last written.
- **Overall risk rating**: **Critical** — unprivileged, total fund loss is reachable two ways (F-001, F-002).

### 2. Findings

> **F-001 — `emergency_drain` is public and unbounded**
> **Severity:** Critical
> **Class:** Auth bypass
> **Location:** `src/lib.rs:119`
> **What:** `emergency_drain` is declared `PUBLIC` (`src/lib.rs:30`) and calls `self.vault.take_all()` (`src/lib.rs:120`), so any caller can empty the vault in a single transaction.
> **Why it matters:** Total, immediate loss of all deposited XRD, by anyone.
> **Suggested direction:** Gate it behind `admin` (or a dedicated owner role) and bound it with a per-call cap and an epoch cooldown rather than draining everything at once.

> **F-002 — `set_oracle_price` is public, single-source, and unchecked**
> **Severity:** Critical
> **Class:** Oracle / price dependence
> **Location:** `src/lib.rs:111`
> **What:** Anyone can call `set_oracle_price` (`src/lib.rs:29`) to set any price with no staleness or sanity bound, then `deposit`/`withdraw` against that price in the same transaction.
> **Why it matters:** An attacker sets a favourable price, mints or redeems shares, and extracts value — a second drain path, independent of F-001.
> **Suggested direction:** Make price updates privileged, source them from a real (ideally multi-source) external oracle, and add staleness + deviation bounds before a price becomes usable.

> **F-003 — `deposit` share math divides by zero and can overflow**
> **Severity:** High
> **Class:** Integer / decimal arithmetic
> **Location:** `src/lib.rs:87`
> **What:** `shares = amount * self.oracle.price / total_value * self.total_shares` uses raw `*`/`/`; on the first deposit `total_value` is `0` (`src/lib.rs:86`) so the division panics, and the chained multiply can overflow `Decimal`.
> **Why it matters:** The first deposit always reverts (the vault can't be bootstrapped), and the formula is wrong even when it doesn't panic.
> **Suggested direction:** Special-case the first deposit, use `checked_mul`/`checked_div`, and define an explicit share formula with documented, vault-favouring rounding.

> **F-004 — `withdraw` ignores the pause flag**
> **Severity:** High
> **Class:** State machine
> **Location:** `src/lib.rs:94`
> **What:** `withdraw` never checks `self.paused` (`src/lib.rs:95`–`101`), so withdrawals proceed while the vault is paused.
> **Why it matters:** Pause is the emergency brake; if it doesn't cover exits it can't contain an incident — and it leaves F-002's price-manipulation drain unstoppable.
> **Suggested direction:** Assert `!self.paused` at the top of `withdraw` (and any other value-moving method) so the circuit breaker covers exits, not just admin ops.

> **F-005 — `unpause` epoch check is off by one**
> **Severity:** Medium
> **Class:** Time / epoch checks
> **Location:** `src/lib.rs:132`
> **What:** The assert requires `current_epoch > unlock_epoch` (`src/lib.rs:132`) — one epoch — but the message and intent promise "2 full epochs".
> **Why it matters:** The minimum-pause window is half what's documented, weakening the delay the brake is meant to provide.
> **Suggested direction:** Compare against `unlock_epoch + 2`, and add an at-boundary test so the enforced delay matches the intended one.

> **F-006 — `admin` can rotate itself and there is no owner**
> **Severity:** Medium
> **Class:** Upgrade safety
> **Location:** `src/lib.rs:23`
> **What:** `admin => updatable_by: [admin]` (`src/lib.rs:23`) lets the admin role rewrite its own rule, and the component globalizes with `OwnerRole::None` (`src/lib.rs:72`) — no higher authority exists.
> **Why it matters:** A compromised or fat-fingered admin is unrecoverable; there is no owner to rotate or freeze it.
> **Suggested direction:** Introduce an `owner` role that governs `admin`, and make `admin` `updatable_by` the owner only.

> **F-007 — `set_fee_bps` has no upper bound**
> **Severity:** Medium
> **Class:** Integer / decimal arithmetic
> **Location:** `src/lib.rs:106`
> **What:** `set_fee_bps` stores `bps` directly (`src/lib.rs:106`) with no range check, so the fee can be set above 100%.
> **Why it matters:** A bad or malicious fee can make the vault unusable or silently expropriate depositors.
> **Suggested direction:** Assert an explicit ceiling (e.g. `bps <= dec!(1000)`) and reject out-of-range values.

> **F-008 — no events on state-changing methods**
> **Severity:** Low
> **Class:** Event emission
> **Location:** `src/lib.rs:82`
> **What:** `deposit`, `withdraw`, `set_oracle_price`, and `emergency_drain` mutate state but emit no events (`src/lib.rs:82`–`121`).
> **Why it matters:** Off-chain indexers and monitors can't observe deposits, redemptions, price changes, or drains — which also hampers incident detection for F-001/F-002.
> **Suggested direction:** Define and emit an event for each state change, including amounts and the resource address.

### 3. Checklist coverage

**Auth bypass**: see F-001 (and F-002 — both expose privileged effects to `PUBLIC` callers).
**Reentrancy**: not applicable — the blueprint makes no external component calls.
**Integer / decimal arithmetic**: see F-003, F-007.
**Resource handling**: clean — every bucket is deposited, burned, or returned; no `Option<Bucket>` returns or dropped buckets.
**Time / epoch checks**: see F-005.
**State machine**: see F-004.
**External calls / composability**: not applicable — no `extern_blueprint!`, `Global<X>` calls, or `CALL_METHOD` to other components.
**Upgrade safety**: see F-006.
**Oracle / price dependence**: see F-002.
**Slippage / MEV**: see F-002 — `deposit`/`withdraw` take no caller `min_out`, so against the mutable price they are sandwichable; there is no per-trade slippage bound.
**Approvals / allowances**: not applicable — no long-lived proofs or access-rule grants are handed to external parties.

### 4. Pattern conformance

> **Owner/admin role separation** — strategy-vault-threat-model.md
> **Present:** no
> **Where / why missing:** Only a self-rotating `admin` with `OwnerRole::None` (`src/lib.rs:23`, `src/lib.rs:72`); a cold owner over a hot admin would bound F-001 and F-006.

> **Per-call cap + cooldown on emergency withdraw** — strategy-vault-threat-model.md
> **Present:** no
> **Where / why missing:** `emergency_drain` takes the whole vault in one call (`src/lib.rs:120`); a fractional cap plus an epoch cooldown would limit the blast radius.

> **Multi-source, staleness-checked oracle** — strategy-vault-threat-model.md
> **Present:** no
> **Where / why missing:** Price is a single mutable field with no freshness or deviation check (`src/lib.rs:40`, `src/lib.rs:111`).

> **Rounding in the vault's favour** — caviarnine-hyperstake-patterns.md
> **Present:** no
> **Where / why missing:** Share math uses raw operators with implicit rounding (`src/lib.rs:87`); `take_advanced`-style directional rounding would protect the vault.

> **Circuit breaker that covers exits** — ignition-patterns.md
> **Present:** partial
> **Where / why missing:** A `paused` flag exists but `withdraw` ignores it (`src/lib.rs:95`); the breaker stops admin ops, not value flows.

### 5. Test coverage gaps

- `withdraw` has **zero** tests — `tests/vault.rs` exercises only `deposit` (`tests/vault.rs:13`).
- No auth-violation test: nothing asserts a non-`admin` caller is rejected by `set_fee_bps`/`pause`/`unpause` (negative path untested).
- No "withdraw while paused" test — a single negative case would catch F-004.
- `set_oracle_price` and `emergency_drain` have no tests at all, success or failure.
- `unpause`'s epoch boundary (F-005) is untested — no at-boundary or over-boundary case.

### 6. Open questions for the human auditor

- Is `set_oracle_price` public by intent (e.g. a permissionless keeper)? Even so, it needs staleness and sanity bounds before the price is used (`src/lib.rs:111`).
- Should `deposit`/`withdraw` accept a caller-supplied `min_shares_out` / `min_amount_out` to resist sandwiching given the mutable price (`src/lib.rs:82`)?
- Is a governance/owner layer above `admin` intended? `OwnerRole::None` currently leaves no recovery path if the admin badge is lost or compromised (`src/lib.rs:72`).
