# Scrypto Vulnerability Checklist

Eleven classes of issues to walk through for every audit. Each class lists concrete questions; if the answer to any question is "no", that's a finding.

This list is conservative — it favours false positives over false negatives. The audit prompt instructs the model to mark a class **not applicable** with a one-sentence justification when the blueprint genuinely doesn't have exposure to that class. That's preferable to silent omission.

---

## 1. Auth bypass

- Does every state-changing public method have an `enable_method_auth!` rule?
- Is the rule **least-privilege** — i.e. would a strictly narrower role still work?
- Are role rules `updatable_by` an *equal-or-higher* role only? (A manager rotating itself is fine; a manager rotating the owner is a bug.)
- Are there methods marked `PUBLIC` that should be role-gated? Look especially at methods that move resources, mutate fee parameters, or change registry entries.
- Is the role check performed **before** any state mutation? (Scrypto enforces this at the method boundary, but custom proof checks inside method bodies need to come first.)
- Is `withdraw` (or whatever the user-exit method is) gated only by the owner role, with **no** secondary policy hooks that could refuse the call?

## 2. Reentrancy

- Does the blueprint make external calls (`Global<X>.method(...)`, `extern_blueprint!`, or `ScryptoVmV1Api::object_call`)?
- For each such call, is the component's state finalised **before** the call? Specifically, are vault deposits / withdrawals / KVS mutations completed before any external invocation that could trigger a callback?
- If a malicious component on the other end of an external call re-entered this blueprint, would it see consistent state? (Scrypto's resource model prevents many classic reentrancies, but proof-of-resource flows and callback patterns can still expose pre-mutation state.)

## 3. Integer / decimal arithmetic

- Are there unbounded multiplications? (`Decimal::checked_mul` returns `Option`; raw `*` panics on overflow.)
- Are there divisions where the divisor could be zero? (`Decimal::checked_div` returns `Option`; raw `/` panics.)
- Is precision loss accounted for? (Decimal has finite precision; chained multiply-then-divide can drop bits silently.)
- Are rounding directions explicit? Look for `Rounded(RoundingMode::ToZero)` / `ToPositiveInfinity` / `ToNegativeInfinity`. Implicit rounding (default for `Decimal::checked_mul`) can favour the user against the vault.
- Are any computations using `f32`/`f64`? Floats have no place in financial scrypto. (Unlikely but worth scanning.)
- For `take_advanced(amount, strategy)`: is the strategy correct for the side of the trade? Outgoing-from-vault should round **down** (vault favoured); incoming-to-vault should round **up**.

## 4. Resource handling

- Are buckets always either deposited, returned, or burned? A lost bucket (variable dropped without consumption) is a fatal Scrypto error at the engine level, but it indicates a logic bug that should be flagged.
- Are vault sizes bounded somewhere? Unbounded vault growth in `KeyValueStore<X, Vault>` is fine *per entry* but the *number of entries* may have implications (gas, iteration cost).
- For NFT minting: is there an `id_collision` risk? (Auto-incremented IDs are safe; user-supplied IDs need a uniqueness check.)
- Does any method return a bucket that the caller might forget to handle? Use of `Option<Bucket>` is a smell — the caller's manifest must handle both cases.

## 5. Time / epoch checks

- Is every time-locked method actually time-locked? Look for `Clock::current_time_*` or epoch arithmetic.
- Is the staleness threshold reasonable? (Hours / days, not seconds for an oracle in most cases.)
- Is the comparison direction correct? Off-by-one (`<` vs `<=`, `>` vs `>=`) is the classic time-lock bug.
- For "matured after N seconds" patterns: what's the unit? Mixing seconds / minutes / epochs in arithmetic is dangerous.

## 6. State machine

- Does the blueprint have phases (e.g. `Pending` / `Funded` / `Closed`)? If so, is every method that depends on a phase actually checking it?
- Are transitions one-way where they should be? (A `Closed` task that can return to `Pending` may enable replay attacks.)
- Is there an idempotency check on signal-driven methods? If the same input is replayed (e.g. by a watcher restarting), does the second call no-op or duplicate?
- Are invariants (e.g. `nav == sum_of_vaults + sum_of_positions`) checked anywhere? At minimum, the test suite should assert these after every method.

## 7. External calls / composability

- Is every external component address either passed in at instantiation (and stored), build-time-injected via `env!()`, or whitelisted in a KVS? Hardcoded addresses in method bodies are brittle.
- Is the return value of every external call inspected? Discarding the return of an external swap (and assuming success) is a footgun.
- Are external calls inside loops? A pool that intentionally consumes all your fee budget by ballooning gas usage can DOS you.
- Are there CALL_METHOD invocations to addresses not in the whitelist? If so, where does the whitelist live and who can change it?

## 8. Upgrade safety

- Is the blueprint upgradeable? If yes: does the upgrade path preserve storage layout? (Field reordering / insertion / renaming = storage slot collisions.)
- Are role rotations atomic? If `protocol_owner` rotates itself, does it require the new owner to accept (two-step) or can the rotation lose the badge mid-flight?
- For NFT receipt patterns: does the receipt's `#[mutable]` field have all the fields it might need in v2? Adding fields after launch is non-trivial.

## 9. Oracle / price dependence

- Does the blueprint depend on a price oracle? If yes:
  - Is it **multi-source**? Single-source dependence is the #1 DeFi exploit vector.
  - Is there a staleness check? (See §5.)
  - Are there sanity bounds on oracle output? (E.g. "if oracle says XRD = $1000, refuse.")
  - Is there a TWAP / median fallback if the spot oracle is manipulated?
- For pool-as-oracle patterns (reading a pool's `price()` method): how does the blueprint behave if the pool is shallow / drained / manipulated?

## 10. Slippage / MEV

- Is `min_out` (or equivalent) computed and passed into every swap?
- Is there a post-trade NAV check ("after this trade, NAV must be >= pre-trade NAV * (1 - max_slippage_bps/10000)")?
- For batch operations (multi-leg swaps): is each leg's slippage cap enforced independently, or only the final state? Per-leg is safer.
- Is there a cumulative slippage budget (rolling window)? Per-trade caps don't prevent death-by-1000-cuts.
- For mempool exposure: are entries / exits time-randomised, ordered, or otherwise resistant to sandwich attacks? (Radix's deterministic ordering helps but is not bulletproof.)

## 11. Approvals / allowances

- Are there any long-lived authorizations (badges, proofs, access-rule grants) handed to external components?
- If yes: is there a `revoke` path? Who can call it? How quickly does it take effect?
- Are there `Proof` objects passed into methods that the method holds longer than necessary? A proof captured into a local variable can be re-used unexpectedly.
- For composed access rules (`require_amount(2, signers)`, `count_of(n, [...])`): are the underlying badges actually distinct holders, or could one entity satisfy multiple slots?

---

## Cross-cutting

These don't fit neatly into one class but every audit should consider them:

- **Error messages**: Are errors descriptive (`define_error!` macro pattern) or are they `panic!("oops")`-grade? Generic panics make post-mortems hard.
- **Test coverage**: Every public method should have at least one positive and one negative test. Every cap should have an at-cap and an over-cap test. Every role should have an auth-violation test.
- **Event emission**: Are events emitted for every state change consumers might care about? Missing events break off-chain indexers.
- **`unwrap()` / `expect()`**: Any of these on user-supplied input is a finding. Internal invariants are okay if the panic message is clear.
- **Mutable globals**: No, this is Rust. (But check anyway.)
